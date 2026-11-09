"""Tests for the PI runtime source-log recorder (``PIRunRecorder``), the source-class map, selectors and the conflict check.

HTTP failures are recorded as failures, never as negatives (verifier defect D1).

Everything is offline. Graph dicts are hand-built, agents are faked with coroutines or ``AsyncMock``.
"""

# Replaces: test_pi_runtime.py (consolidated 2026-11-09).

from __future__ import annotations

import asyncio
from typing import Dict, List, Optional

import pytest
from pi_helpers import make_graph as _graph
from pi_helpers import make_node as _node
from pi_helpers import make_receipt as _receipt

from bunnyhole.engine.graph import InvestigationGraph
from bunnyhole.engine.models import DomainCategory
from bunnyhole.engine.pi_analysis import SOURCE_CLASSES
from bunnyhole.engine.pi_runtime import (
    SOURCE_CLASS_MAP,
    PIRunRecorder,
    run_conflict_check,
    selectors_from_seeds,
)

# ----------------------------------------------------------------------------------------------
# PIRunRecorder
# ----------------------------------------------------------------------------------------------


def test_recorder_hit_when_new_node_and_receipt_appear():
    g = _graph()
    rec = PIRunRecorder()

    async def agent() -> str:
        g.upsert_node(_node("lei:1", receipts=[_receipt("gleif", "https://x/1")]))
        return "done"

    out = asyncio.run(rec.run("gleif", "Acme", g, agent()))
    assert out == "done"  # the coroutine's result is passed through
    assert [(e.source, e.target, e.status) for e in rec.entries] == [("gleif", "Acme", "hit")]
    assert "1 new node" in rec.entries[0].detail
    assert rec.entries[0].at_utc


def test_recorder_negative_when_agent_only_logs_info():
    g = _graph()
    rec = PIRunRecorder()

    async def agent() -> None:
        g.log(DomainCategory.FIAT, "SEC_EDGAR_INFO", "Acme", "nothing found")

    asyncio.run(rec.run("sec_edgar", "Acme", g, agent()))
    assert rec.entries[0].status == "negative"


def test_recorder_negative_when_merge_adds_no_new_receipt():
    g = _graph()
    r = _receipt("gleif", "https://x/1")
    g.upsert_node(_node("lei:1", receipts=[r]))
    rec = PIRunRecorder()

    async def agent() -> None:
        g.upsert_node(_node("lei:1", receipts=[r]))  # same receipt re-found: not new information

    asyncio.run(rec.run("gleif", "Acme", g, agent()))
    assert rec.entries[0].status == "negative"


def test_recorder_skipped_on_skip_event_with_detail():
    g = _graph()
    rec = PIRunRecorder()

    async def agent() -> None:
        g.log(DomainCategory.FIAT, "UK_PSC_SCAN", "Acme", "scanning")
        g.log(DomainCategory.FIAT, "UK_PSC_SKIP", "Acme", "UK_COMPANIES_HOUSE_API_KEY not set", level="warning")

    asyncio.run(rec.run("uk_psc", "Acme", g, agent()))
    assert rec.entries[0].status == "skipped"
    assert "API_KEY not set" in rec.entries[0].detail


def test_recorder_hit_beats_skip_but_notes_the_partial_failure():
    g = _graph()
    rec = PIRunRecorder()

    async def agent() -> None:
        g.log(DomainCategory.FIAT, "UK_PSC_SKIP", "n1", "PSC lookup failed for company n1", level="warning")
        g.upsert_node(_node("company:uk:2", receipts=[_receipt("companies_house", "https://ch/2")]))

    asyncio.run(rec.run("uk_psc", "Acme", g, agent()))
    assert rec.entries[0].status == "hit"
    assert "partial" in rec.entries[0].detail and "n1" in rec.entries[0].detail


def test_recorder_exception_becomes_error_entry_and_is_not_raised():
    g = _graph()
    rec = PIRunRecorder()

    async def agent() -> None:
        raise ValueError("boom")

    out = asyncio.run(rec.run("court_dockets", "Acme", g, agent()))
    assert out is None
    assert rec.entries[0].status == "error"
    assert rec.entries[0].detail == "ValueError: boom"


def test_recorder_skip_records_policy_skip():
    rec = PIRunRecorder()
    rec.skip("credential_combo", "credential:***", "credential/breach contents are not used in PI mode")
    entry = rec.entries[0]
    assert (entry.source, entry.status) == ("credential_combo", "skipped")
    assert "not used in PI mode" in entry.detail


def test_recorder_attributes_concurrent_calls_correctly():
    g = _graph()
    rec = PIRunRecorder()

    async def finder() -> None:
        await asyncio.sleep(0)
        g.upsert_node(_node("lei:9", receipts=[_receipt("gleif", "https://x/9")]))
        await asyncio.sleep(0)

    async def skipper() -> None:
        await asyncio.sleep(0)
        g.log(DomainCategory.FIAT, "CFPB_COMPLAINTS_SKIP", "Acme", "HTTP 500", level="warning")
        await asyncio.sleep(0)

    async def nothing() -> None:
        await asyncio.sleep(0)
        await asyncio.sleep(0)

    async def main() -> None:
        await asyncio.gather(
            rec.run("gleif", "Acme", g, finder()),
            rec.run("cfpb_complaints", "Acme", g, skipper()),
            rec.run("wikidata", "Acme", g, nothing()),
        )

    asyncio.run(main())
    status = {e.source: e.status for e in rec.entries}
    assert status == {"gleif": "hit", "cfpb_complaints": "skipped", "wikidata": "negative"}


def test_recorder_ignores_activity_outside_a_run_and_does_not_credit_it_later():
    g = _graph()
    rec = PIRunRecorder()

    async def main() -> None:
        async def first() -> None:
            await asyncio.sleep(0)

        await rec.run("a", "x", g, first())  # attaches to the graph
        g.upsert_node(_node("lei:7", receipts=[_receipt("other", "https://x/7")]))  # outside any run
        await rec.run("b", "x", g, first())

    asyncio.run(main())
    assert [e.status for e in rec.entries] == ["negative", "negative"]


def test_recorder_counts_nodes_already_in_graph_at_first_attach_as_old():
    g = _graph()
    g.upsert_node(_node("seed:1", receipts=[_receipt("bunnyhole_case_director", "seed://x")]))
    rec = PIRunRecorder()

    async def agent() -> None:
        g.upsert_node(_node("seed:1", receipts=[_receipt("bunnyhole_case_director", "seed://x")]))

    asyncio.run(rec.run("gleif", "x", g, agent()))
    assert rec.entries[0].status == "negative"


# ----------------------------------------------------------------------------------------------
# recorder: HTTP failures are not negatives (verifier defect D1)
# ----------------------------------------------------------------------------------------------


def _http_agent(url: str, status: int, graph: Optional[InvestigationGraph] = None, add_node: bool = False):
    """A coroutine that behaves like a journalist agent: swallow non-200 silently, optionally add a node."""
    import httpx

    async def agent() -> None:
        async with httpx.AsyncClient(timeout=5.0) as client:
            resp = await client.get(url)
            if resp.status_code != 200:
                return  # exactly what JournalistAgent.investigate_court_dockets does
            if add_node and graph is not None:
                graph.upsert_node(_node("docket:1", receipts=[_receipt("courtlistener_recap_v4", "https://cl/1")]))

    return agent()


def _run_http(recorder: PIRunRecorder, graph: InvestigationGraph, source: str, coros: list) -> None:
    async def main() -> None:
        for coro in coros:
            await recorder.run(source, "Acme", graph, coro)

    asyncio.run(main())


def test_http_401_with_no_nodes_is_skipped_not_negative():
    import respx

    g, rec = _graph(), PIRunRecorder()
    with respx.mock:
        respx.get("https://www.courtlistener.com/api/rest/v4/search/").respond(401)
        _run_http(rec, g, "court_dockets", [_http_agent("https://www.courtlistener.com/api/rest/v4/search/?q=x", 401)])
    entry = rec.entries[0]
    assert entry.status == "skipped"
    assert "HTTP 401 from www.courtlistener.com" in entry.detail


@pytest.mark.parametrize("status", [403, 429])
def test_http_403_and_429_with_no_nodes_are_skipped(status: int):
    import respx

    g, rec = _graph(), PIRunRecorder()
    with respx.mock:
        respx.get("https://api.example.org/x").respond(status)
        _run_http(rec, g, "cfpb_complaints", [_http_agent("https://api.example.org/x", status)])
    assert rec.entries[0].status == "skipped"
    assert f"HTTP {status} from api.example.org" in rec.entries[0].detail


@pytest.mark.parametrize("status", [400, 404, 500, 503])
def test_other_http_errors_with_no_nodes_are_errors(status: int):
    import respx

    g, rec = _graph(), PIRunRecorder()
    with respx.mock:
        respx.get("https://api.example.org/x").respond(status)
        _run_http(rec, g, "court_dockets", [_http_agent("https://api.example.org/x", status)])
    assert rec.entries[0].status == "error"
    assert f"HTTP {status} from api.example.org" in rec.entries[0].detail


def test_transport_error_swallowed_by_the_agent_is_an_error_entry():
    import httpx
    import respx

    g, rec = _graph(), PIRunRecorder()

    async def agent() -> None:
        try:
            async with httpx.AsyncClient() as client:
                await client.get("https://down.example.org/")
        except httpx.HTTPError:
            return  # agents commonly swallow this

    with respx.mock:
        respx.get("https://down.example.org/").mock(side_effect=httpx.ConnectError("refused"))
        _run_http(rec, g, "wayback", [agent()])
    assert rec.entries[0].status == "error"
    assert "ConnectError from down.example.org" in rec.entries[0].detail


def test_http_failure_with_new_nodes_is_a_hit_that_notes_the_partial_failure():
    import httpx
    import respx

    g, rec = _graph(), PIRunRecorder()

    async def agent() -> None:
        async with httpx.AsyncClient() as client:
            await client.get("https://down.example.org/a")  # 500, ignored
            await client.get("https://ok.example.org/b")
            g.upsert_node(_node("lei:1", receipts=[_receipt("gleif", "https://x/1")]))

    with respx.mock:
        respx.get("https://down.example.org/a").respond(500)
        respx.get("https://ok.example.org/b").respond(200)
        _run_http(rec, g, "gleif", [agent()])
    entry = rec.entries[0]
    assert entry.status == "hit"
    assert "partial failures" in entry.detail and "HTTP 500 from down.example.org" in entry.detail


def test_successful_http_with_nothing_new_stays_negative_and_says_how_many_responses():
    import respx

    g, rec = _graph(), PIRunRecorder()
    with respx.mock:
        respx.get("https://api.example.org/x").respond(200, json={"results": []})
        _run_http(rec, g, "court_dockets", [_http_agent("https://api.example.org/x", 200)])
    entry = rec.entries[0]
    assert entry.status == "negative"
    assert entry.detail.startswith("ran; no new nodes or receipts")
    assert "1 HTTP response" in entry.detail


def test_skip_event_still_beats_a_clean_negative_when_no_http_was_observed():
    g, rec = _graph(), PIRunRecorder()

    async def agent() -> None:
        g.log(DomainCategory.FIAT, "COURTLISTENER_SKIP", "Acme", "no API token", level="warning")

    asyncio.run(rec.run("court_dockets", "Acme", g, agent()))
    assert rec.entries[0].status == "skipped"


def test_failures_are_attributed_to_the_right_concurrent_source():
    import httpx
    import respx

    g, rec = _graph(), PIRunRecorder()

    async def failing() -> None:
        async with httpx.AsyncClient() as client:
            await asyncio.sleep(0)
            await client.get("https://a.example.org/x")

    async def healthy() -> None:
        async with httpx.AsyncClient() as client:
            await asyncio.sleep(0)
            await client.get("https://b.example.org/x")

    async def main() -> None:
        await asyncio.gather(rec.run("court_dockets", "Acme", g, failing()), rec.run("wayback", "Acme", g, healthy()))

    with respx.mock:
        respx.get("https://a.example.org/x").respond(401)
        respx.get("https://b.example.org/x").respond(200)
        asyncio.run(main())
    status = {e.source: e.status for e in rec.entries}
    assert status == {"court_dockets": "skipped", "wayback": "negative"}


def test_observer_is_registered_only_while_a_run_is_in_flight_and_httpx_is_restored():
    import httpx

    from bunnyhole.engine import netutil

    original = httpx.AsyncClient.send
    g, rec = _graph(), PIRunRecorder()
    seen_during: list = []

    async def agent() -> None:
        seen_during.append(netutil.get_response_observer())

    asyncio.run(rec.run("gleif", "Acme", g, agent()))
    assert seen_during and seen_during[0] is not None
    assert netutil.get_response_observer() is None
    assert httpx.AsyncClient.send is original


def test_recorder_does_not_clobber_an_observer_someone_else_registered():
    from bunnyhole.engine import netutil

    mine = lambda url, status, error: None  # noqa: E731
    netutil.set_response_observer(mine)
    try:
        g, rec = _graph(), PIRunRecorder()

        async def agent() -> None:
            return None

        asyncio.run(rec.run("gleif", "Acme", g, agent()))
        assert netutil.get_response_observer() is mine
    finally:
        netutil.set_response_observer(None)


def test_http_activity_outside_any_run_is_ignored():
    import httpx
    import respx

    from bunnyhole.engine import netutil

    g, rec = _graph(), PIRunRecorder()

    async def main() -> None:
        async def quiet() -> None:
            return None

        await rec.run("gleif", "Acme", g, quiet())
        async with httpx.AsyncClient() as client:  # observer is gone: nothing to attribute
            await client.get("https://api.example.org/x")

    with respx.mock:
        respx.get("https://api.example.org/x").respond(500)
        asyncio.run(main())
    assert [e.status for e in rec.entries] == ["negative"]
    assert netutil.get_response_observer() is None


# ----------------------------------------------------------------------------------------------
# SOURCE_CLASS_MAP / selectors
# ----------------------------------------------------------------------------------------------


def test_source_class_map_values_are_valid_classes_and_cover_the_recorded_sources():
    assert set(SOURCE_CLASS_MAP.values()) <= set(SOURCE_CLASSES)
    for name in ("gleif", "opensanctions", "sec_edgar", "court_dockets", "news_narrative", "wayback", "uk_psc",
                 "ca_sanctions", "cfpb_complaints", "openalex", "hackernews", "nonprofit_990s"):
        assert name in SOURCE_CLASS_MAP, name
    # reference aids must not inflate coverage
    assert "wikidata" not in SOURCE_CLASS_MAP and "wikipedia" not in SOURCE_CLASS_MAP
    assert SOURCE_CLASS_MAP["uk_psc"] == "beneficial_ownership"
    assert SOURCE_CLASS_MAP["ca_sanctions"] == "sanctions_pep"


def test_selectors_from_seeds_maps_lead_types_and_ignores_secrets():
    seeds = [
        ("company", "John Smith"), ("email", "a@b.co"), ("phone", "+15550100"), ("username", "jsmith1"),
        ("wallet", "0x" + "a" * 40), ("domain", "acme.io"), ("credential", "a@b.co:hunter2"), ("document", "x.pdf"),
    ]
    person = selectors_from_seeds(seeds, subject_is_person=True)
    assert person["names"] == ["John Smith"] and "organizations" not in person
    assert person["emails"] == ["a@b.co"] and person["domains"] == ["acme.io"]
    assert person["usernames"] == ["jsmith1"] and person["wallets"] == ["0x" + "a" * 40]
    assert "hunter2" not in str(person)
    entity = selectors_from_seeds(seeds, subject_is_person=False)
    assert entity["organizations"] == ["John Smith"] and "names" not in entity


# ----------------------------------------------------------------------------------------------
# conflict check
# ----------------------------------------------------------------------------------------------


class _FakeStore:
    def __init__(self, rows: Optional[Dict[str, List[dict]]] = None, boom: Optional[Exception] = None) -> None:
        self.rows = rows or {}
        self.boom = boom
        self.queries: List[str] = []

    def search_entity_memory(self, query: str, limit: int = 25) -> List[dict]:
        self.queries.append(query)
        if self.boom:
            raise self.boom
        return self.rows.get(query, [])


def test_conflict_check_returns_deduped_prior_cases_and_logs_hit():
    row = {"entity_id": "lei:1", "label": "Acme", "case_id": "bh_old", "seed_query": "Acme", "sighted_at": "2026-01-01"}
    store = _FakeStore({"Acme": [row, dict(row, entity_id="lei:2")], "acme.io": [row]})
    rec = PIRunRecorder()
    prior = run_conflict_check(store, ["Acme", "acme.io", "ab"], "bh_now", rec)
    assert [p["case_id"] for p in prior] == ["bh_old"]  # deduped by case
    assert prior[0]["seed"] == "Acme" and prior[0]["at"] == "2026-01-01"
    assert "ab" not in store.queries  # too short to search without matching everything
    assert [e.status for e in rec.entries] == ["hit"]


def test_conflict_check_excludes_current_case_and_logs_negative():
    row = {"entity_id": "x", "label": "Acme", "case_id": "bh_now", "seed_query": "Acme", "sighted_at": "t"}
    rec = PIRunRecorder()
    assert run_conflict_check(_FakeStore({"Acme": [row]}), ["Acme"], "bh_now", rec) == []
    assert rec.entries[0].status == "negative"


def test_conflict_check_failure_is_non_fatal_and_recorded_as_error():
    rec = PIRunRecorder()
    prior = run_conflict_check(_FakeStore(boom=RuntimeError("db locked")), ["Acme"], "bh_now", rec)
    assert prior == []
    assert rec.entries[0].status == "error" and "RuntimeError: db locked" in rec.entries[0].detail
