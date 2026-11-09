"""Tests for the PI runtime: the source-log recorder, block assembly and the orchestrator wiring.

Everything is offline. Graph dicts are hand-built, agents are faked with coroutines or ``AsyncMock``.
"""

from __future__ import annotations

import asyncio
from typing import Any, Dict, List, Optional
from unittest.mock import AsyncMock

import pytest

from bunnyhole.engine import pi_runtime
from bunnyhole.engine.graph import InvestigationGraph
from bunnyhole.engine.models import (
    DomainCategory,
    EntityType,
    EvidenceReceipt,
    GraphEdge,
    GraphNode,
    RelationType,
)
from bunnyhole.engine.orchestrator import BunnyholeOrchestrator
from bunnyhole.engine.personas import Persona
from bunnyhole.engine.pi import (
    CaseType,
    FindingLabel,
    PIBlock,
    PIEngagement,
    SourceLogEntry,
)
from bunnyhole.engine.pi_analysis import SOURCE_CLASSES
from bunnyhole.engine.pi_runtime import (
    SOURCE_CLASS_MAP,
    PIRunRecorder,
    assemble_pi_block,
    run_conflict_check,
    selectors_from_seeds,
)
from bunnyhole.engine.profile import InvestigatorProfile

NOW = "2026-11-09T00:00:00+00:00"


# ----------------------------------------------------------------------------------------------
# helpers
# ----------------------------------------------------------------------------------------------


def _graph() -> InvestigationGraph:
    return InvestigationGraph("pi_test", "Acme Holdings Ltd")


def _receipt(tool: str, url: str, fact: str = "fact") -> EvidenceReceipt:
    return EvidenceReceipt(tool=tool, domain=DomainCategory.FIAT, source_url=url, extracted_fact=fact)


def _node(node_id: str, label: str = "", etype: EntityType = EntityType.ORGANIZATION, **kw: Any) -> GraphNode:
    return GraphNode(id=node_id, label=label or node_id, entity_type=etype, domain=DomainCategory.FIAT, **kw)


def _engagement(case_type: CaseType = CaseType.DUE_DILIGENCE, **kw: Any) -> PIEngagement:
    kw.setdefault("subject_is_person", False)
    kw.setdefault("purpose_category", "counterparty_due_diligence")
    if kw["subject_is_person"]:
        kw.setdefault("matter_ref", "MSA-2026-114")
    return PIEngagement.build(case_type, "Vet a counterparty before signing a supply contract", **kw)


# plain-dict builders (what compile_full_result hands to assemble_pi_block after to_dict())
def _rc(tool: str, url: str = "", rid: str = "", ts: str = NOW) -> Dict[str, Any]:
    return {
        "receipt_id": rid or f"rcpt_{tool}_{abs(hash(url)) % 10_000}",
        "tool": tool,
        "source_url": url,
        "sha256_proof": "ab" * 32,
        "timestamp": ts,
        "extracted_fact": "f",
    }


def _nd(node_id: str, etype: str = "Organization", label: str = "", receipts: Optional[list] = None,
        attrs: Optional[dict] = None, flags: Optional[list] = None) -> Dict[str, Any]:
    return {
        "id": node_id,
        "label": label or node_id,
        "entity_type": etype,
        "receipts": receipts or [],
        "attributes": attrs or {},
        "risk_flags": flags or [],
    }


def _ed(src: str, rel: str, dst: str, receipts: Optional[list] = None, event_date: Optional[str] = None) -> Dict[str, Any]:
    return {
        "id": f"edge_{src}_{rel}_{dst}",
        "source_id": src,
        "target_id": dst,
        "relation": rel,
        "receipts": receipts or [],
        "event_date": event_date,
    }


def _assemble(nodes: list, edges: Optional[list] = None, timeline: Optional[list] = None, **kw: Any) -> PIBlock:
    eng = kw.pop("engagement", None) or _engagement()
    log = kw.pop("source_log", [])
    graph_dict = {"nodes": nodes, "edges": edges or [], "timeline": timeline or []}
    return assemble_pi_block(
        eng, graph_dict, log,
        cross_case_prior=kw.pop("cross_case_prior", []),
        selectors=kw.pop("selectors", {}),
        ownership_links=kw.pop("ownership_links", []),
        now_iso=NOW,
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


# ----------------------------------------------------------------------------------------------
# assemble_pi_block: findings and freshness
# ----------------------------------------------------------------------------------------------


def test_findings_are_labelled_by_independent_sources_and_internal_receipts_do_not_count():
    nodes = [
        _nd("lei:3", receipts=[_rc("gleif", "https://g/1"), _rc("sec_edgar", "https://s/1"), _rc("wayback", "https://w/1")]),
        _nd("lei:2", receipts=[_rc("gleif", "https://g/2"), _rc("sec_edgar", "https://s/2")]),
        _nd("lei:1", receipts=[_rc("gleif", "https://g/3")]),
        _nd("seed:x", receipts=[_rc("bunnyhole_case_director", "seed://x"), _rc("sqlite_cross_case_memory", "sqlite:///x")]),
    ]
    block = _assemble(nodes)
    by_id = {f.node_id: f for f in block.findings}
    assert by_id["lei:3"].finding_label is FindingLabel.CONFIRMED and by_id["lei:3"].source_count == 3
    assert by_id["lei:2"].finding_label is FindingLabel.PROBABLE
    assert by_id["lei:1"].finding_label is FindingLabel.LEAD
    assert "seed:x" not in by_id  # internal receipts only: the anchor is not a finding


def test_shared_source_url_counts_once_in_findings():
    nodes = [_nd("n1", receipts=[_rc("a", "https://same/page"), _rc("b", "https://same/page/")])]
    assert _assemble(nodes).findings[0].source_count == 1


def test_freshness_uses_dates_the_record_carries_never_the_collection_time():
    nodes = [
        _nd("lei:old", receipts=[_rc("gleif", "https://g/1")], attrs={"last_updated": "2020-01-01"}),
        _nd("psc:new", etype="Person", receipts=[_rc("companies_house", "https://c/1")], attrs={"notified_on": "2026-06-01"}),
        _nd("n:none", receipts=[_rc("gleif", "https://g/2")]),
        _nd("n:rcpt", receipts=[dict(_rc("gleif", "https://g/3"), as_of="2025-12-01")]),
    ]
    fresh = {f.node_id: f.freshness for f in _assemble(nodes).findings}
    assert fresh["lei:old"] == "stale"
    assert fresh["psc:new"] == "fresh"
    assert fresh["n:none"] == "unknown"  # receipt timestamps are collection time, not record age
    assert fresh["n:rcpt"] == "fresh"


def test_freshness_falls_back_to_newest_timeline_event_for_the_node():
    nodes = [_nd("lei:1", receipts=[_rc("gleif", "https://g/1")])]
    timeline = [{"timestamp": "2019-01-01T00:00:00Z", "title": "filing", "description": "", "node_ids": ["lei:1"]}]
    assert _assemble(nodes, timeline=timeline).findings[0].freshness == "stale"


# ----------------------------------------------------------------------------------------------
# ownership
# ----------------------------------------------------------------------------------------------


def test_ownership_walks_graph_edges_to_a_natural_person_and_flags_unresolved():
    nodes = [
        _nd("co:child"), _nd("co:mid"), _nd("psc:person", etype="Person"), _nd("lei:orphan"), _nd("co:sub"),
    ]
    edges = [
        _ed("co:mid", "OWNS", "co:child"),
        _ed("psc:person", "OWNS", "co:mid"),
        _ed("lei:orphan", "ULTIMATE_PARENT_OF", "co:sub"),
        _ed("co:child", "SUBSIDIARY_OF", "lei:orphan"),  # child owned by orphan too (reversed direction relation)
    ]
    own = _assemble(nodes, edges).ownership
    pairs = {(e.child, e.parent) for e in own.edges}
    assert ("co:child", "co:mid") in pairs and ("co:mid", "psc:person") in pairs
    assert ("co:sub", "lei:orphan") in pairs and ("co:child", "lei:orphan") in pairs
    assert own.levels_walked == 2
    assert any(u.startswith("lei:orphan") for u in own.unresolved)  # chain stops without a natural person
    assert not any(u.startswith("co:mid") for u in own.unresolved)


def test_director_and_officer_edges_are_control_not_ownership():
    nodes = [_nd("co:a"), _nd("p:dir", etype="Person")]
    own = _assemble(nodes, [_ed("p:dir", "DIRECTOR_OF", "co:a")]).ownership
    assert own.edges == [] and own.unresolved == []


def test_ownership_links_from_psc_are_merged_and_deduplicated():
    nodes = [_nd("company:uk:1"), _nd("psc:uk:1:jane", etype="Person", attrs={"ownership_pct_midpoint": 62.5})]
    edges = [_ed("psc:uk:1:jane", "OWNS", "company:uk:1")]
    links = [
        {"child_id": "company:uk:1", "parent_id": "psc:uk:1:jane", "parent_name": "Jane", "pct": 62.5,
         "is_natural_person": True, "source": "https://ch/psc", "as_of": "2024-01-01"},
        {"child_id": "company:uk:1", "parent_id": "psc:uk:1:holdco", "parent_name": "Holdco", "pct": None,
         "is_natural_person": False, "source": "https://ch/psc", "as_of": ""},
        {"parent_id": "missing-child"},  # malformed: skipped, never raises
    ]
    own = _assemble(nodes, edges, ownership_links=links).ownership
    keys = [(e.child, e.parent) for e in own.edges]
    assert keys.count(("company:uk:1", "psc:uk:1:jane")) == 1
    assert ("company:uk:1", "psc:uk:1:holdco") in keys
    jane = next(e for e in own.edges if e.parent == "psc:uk:1:jane")
    assert jane.pct == 62.5
    assert any(u.startswith("psc:uk:1:holdco") for u in own.unresolved)


def test_50_percent_rule_blocks_majority_owned_child_of_a_listed_node():
    listed = _nd("sanction:X", receipts=[_rc("opensanctions_yente", "https://os/x")])
    nodes = [listed, _nd("co:sub"), _nd("co:subsub")]
    links = [
        {"child_id": "co:sub", "parent_id": "sanction:X", "parent_name": "X", "pct": 60.0, "is_natural_person": False},
        {"child_id": "co:subsub", "parent_id": "co:sub", "parent_name": "Sub", "pct": 55.0, "is_natural_person": False},
    ]
    own = _assemble(nodes, ownership_links=links).ownership
    assert own.blocked_by_50_rule == ["co:sub", "co:subsub"]


def test_50_percent_rule_uses_canadian_sanctions_and_ignores_unlisted_parents():
    nodes = [_nd("sanction:ca:1", receipts=[_rc("gac_sema_sanctions", "https://gac/1")]), _nd("co:a"), _nd("co:b")]
    links = [
        {"child_id": "co:a", "parent_id": "sanction:ca:1", "pct": 50.0},
        {"child_id": "co:b", "parent_id": "co:other", "pct": 90.0},
    ]
    assert _assemble(nodes, ownership_links=links).ownership.blocked_by_50_rule == ["co:a"]


def test_ownership_cycle_does_not_hang():
    nodes = [_nd("co:a"), _nd("co:b")]
    edges = [_ed("co:a", "OWNS", "co:b"), _ed("co:b", "OWNS", "co:a")]
    own = _assemble(nodes, edges).ownership
    assert own.unresolved  # a closed loop never reaches a person


# ----------------------------------------------------------------------------------------------
# false-link flags
# ----------------------------------------------------------------------------------------------


def test_false_link_flags_registered_agent_common_name_nominee_and_hosting():
    nodes = [
        _nd("loc:ra", etype="Location", label="1209 Orange Street, Wilmington", attrs={"full_address": "1209 Orange Street"}),
        _nd("loc:flag", etype="Location", label="Somewhere", flags=["MASS_REGISTERED_AGENT_ADDRESS"]),
        _nd("p:smith", etype="Person", label="\U0001F464 John Smith"),
        _nd("p:nom", etype="Person", label="Nominee Corp Services"),
        _nd("ip:1", etype="IPHost", label="1.2.3.4", attrs={"hosting_provider": "Cloudflare, Inc."}),
        _nd("ip:2", etype="IPHost", label="104.16.0.1", flags=["SHARED_ANYCAST_CDN_IP"]),
        _nd("loc:real", etype="Location", label="12 Quiet Lane", attrs={"full_address": "12 Quiet Lane"}),
    ]
    edges = [_ed("p:nom", "DIRECTOR_OF", f"co:{i}") for i in range(26)]
    flags = _assemble(nodes, edges).false_link_flags
    by_node: Dict[str, List[dict]] = {}
    for f in flags:
        by_node.setdefault(f["node_id"], []).append(f)
    assert {"loc:ra", "loc:flag", "p:smith", "p:nom", "ip:1", "ip:2"} <= set(by_node)
    assert "loc:real" not in by_node
    assert by_node["loc:ra"][0]["severity"] == "high"
    assert "common name" in by_node["p:smith"][0]["reason"]
    assert "26" in by_node["p:nom"][0]["reason"]
    assert all({"node_id", "reason", "severity"} <= set(f) for f in flags)


def test_false_link_flag_for_common_name_selector_of_a_person_subject():
    eng = _engagement(CaseType.BACKGROUND, subject_is_person=True)
    block = _assemble([], engagement=eng, selectors={"names": ["John Smith"]})
    assert any(f["node_id"] == "selector:John Smith" for f in block.false_link_flags)


# ----------------------------------------------------------------------------------------------
# contradictions, gaps, coverage, falsifiers
# ----------------------------------------------------------------------------------------------


def test_timeline_contradictions_and_gaps_are_reported():
    timeline = [
        {"timestamp": "2020-01-01T00:00:00Z", "title": "Acme incorporated", "description": "", "node_ids": ["co:a"]},
        {"timestamp": "2019-01-01T00:00:00Z", "title": "Contract signed", "description": "", "node_ids": ["co:a"]},
        {"timestamp": "2024-06-01T00:00:00Z", "title": "Annual return", "description": "", "node_ids": ["co:a"]},
    ]
    block = _assemble([_nd("co:a")], timeline=timeline)
    assert [c.kind for c in block.contradictions] == ["event_before_incorporation"]
    assert any("co:a" in g for g in block.evidence_gaps)


def test_empty_timeline_reports_no_dated_evidence_gap():
    assert _assemble([]).evidence_gaps == ["No dated evidence at all: the timeline has no usable dated events."]


def test_coverage_counts_only_searched_sources_and_skips_are_not_coverage():
    log = [
        SourceLogEntry(source="gleif", target="Acme", status="negative", at_utc=NOW),
        SourceLogEntry(source="opensanctions", target="Acme", status="skipped", detail="needs key", at_utc=NOW),
        SourceLogEntry(source="court_dockets", target="Acme", status="hit", at_utc=NOW),
    ]
    rows = {r.source_class: r for r in _assemble([], source_log=log).coverage}
    assert rows["corporate_registry"].searched and rows["corporate_registry"].outcome == "negative"
    assert rows["court_dockets"].outcome == "hit"
    assert rows["sanctions_pep"].searched is False and rows["sanctions_pep"].outcome == "not_searched"
    assert [e.status for e in _assemble([], source_log=log).source_log] == ["negative", "skipped", "hit"]


def test_falsifiers_include_unresolved_nodes_and_lead_findings():
    nodes = [_nd("lei:1", receipts=[_rc("gleif", "https://g/1")])]
    edges: list = []
    links = [{"child_id": "lei:1", "parent_id": "lei:parent", "pct": 100.0}]
    block = _assemble(nodes, edges, ownership_links=links)
    text = "\n".join(block.falsifiers)
    assert "lei:parent" in text  # unresolved ownership node
    assert "lei:1" in text  # single-source lead


# ----------------------------------------------------------------------------------------------
# custodians, handoff, custody, envelope
# ----------------------------------------------------------------------------------------------


def test_custodians_are_inferred_from_node_kinds_and_follow_jurisdiction():
    nodes = [
        _nd("domain:acme.io", etype="Domain"),
        _nd("aircraft:n1", etype="Aircraft"),
        _nd("wallet:0x1", etype="CryptoWallet", flags=["CEX_DEPOSIT_SWEEP"]),
        _nd("wallet:0x2", etype="CryptoWallet"),
        _nd("lei:1", receipts=[_rc("gleif", "https://g/1")]),
        _nd("phone:1", etype="Phone"),
        _nd("loc:ra", etype="Location", label="1209 Orange Street"),
    ]
    eng = _engagement(jurisdiction="ca-on")
    block = _assemble(nodes, engagement=eng)
    found = {c.finding for c in block.custodians}
    joined = " | ".join(found).lower()
    assert "deposit address" in joined and "registrant" in joined and "vessel or aircraft" in joined
    assert "registered agent" in joined and "subscriber and line" in joined and "company records" in joined
    assert all(c.jurisdiction == "ca-on" for c in block.custodians)
    assert any("Norwich Pharmacal" in c.instrument for c in block.custodians)
    assert any("Request via counsel" in line for line in block.handoff_sheet)


def test_plain_wallet_without_cex_indicator_does_not_infer_exchange_custodian():
    block = _assemble([_nd("wallet:0x2", etype="CryptoWallet")])
    assert not any("Deposit address" in c.finding for c in block.custodians)


def test_handoff_sheet_lists_selector_identifiers_as_unverified_and_skips_registered_agent_addresses():
    nodes = [
        _nd("loc:ok", etype="Location", attrs={"full_address": "12 Quiet Lane"}),
        _nd("loc:ra", etype="Location", attrs={"full_address": "1209 Orange Street"}),
    ]
    block = _assemble(nodes, selectors={"emails": ["a@b.co"], "phones": ["+15550100"]})
    text = "\n".join(block.handoff_sheet)
    assert "a@b.co" in text and "unverified lead" in text
    assert "12 Quiet Lane" in text and "1209 Orange" not in text


def test_custody_lists_every_node_and_edge_receipt_once():
    shared = _rc("gleif", "https://g/1", rid="rcpt_shared")
    nodes = [_nd("a", receipts=[shared]), _nd("b", receipts=[_rc("x", "https://x", rid="rcpt_x")])]
    edges = [_ed("a", "OWNS", "b", receipts=[shared, _rc("y", "https://y", rid="rcpt_y")])]
    custody = _assemble(nodes, edges).custody
    assert sorted(c.receipt_id for c in custody) == ["rcpt_shared", "rcpt_x", "rcpt_y"]
    one = next(c for c in custody if c.receipt_id == "rcpt_shared")
    assert (one.tool, one.url, one.sha256, one.collected_at_utc) == ("gleif", "https://g/1", "ab" * 32, NOW)


def test_block_envelope_objective_notices_warnings_prior_cases_and_roundtrip():
    eng = _engagement(CaseType.ASSET_SEARCH)
    assert eng.objective == ""
    prior = [{"case_id": "bh_old", "seed": "Acme", "at": "2026-01-01"}]
    block = _assemble([], engagement=eng, cross_case_prior=prior, selectors={})
    assert block.engagement.objective  # filled from the playbook
    assert eng.objective == ""  # input engagement not mutated
    assert block.prior_cases == prior
    assert block.notices and any("not a consumer report" in n for n in block.notices)
    person = _assemble([], engagement=_engagement(CaseType.BACKGROUND, subject_is_person=True), selectors={"names": ["Jo"]})
    assert person.identifier_warnings
    assert PIBlock.model_validate(block.model_dump(mode="json")) == block


def test_assemble_accepts_a_real_graph_to_dict_with_enum_values():
    g = _graph()
    g.upsert_node(_node("lei:p", receipts=[_receipt("gleif", "https://g/p")]))
    g.upsert_node(_node("lei:c", receipts=[_receipt("gleif", "https://g/c")]))
    g.upsert_edge(
        GraphEdge(source_id="lei:p", target_id="lei:c", relation=RelationType.ULTIMATE_PARENT_OF,
                  domain=DomainCategory.FIAT, receipts=[_receipt("gleif", "https://g/e")])
    )
    block = assemble_pi_block(_engagement(), g.to_dict(), [], cross_case_prior=[], selectors={}, ownership_links=[])
    assert ("lei:c", "lei:p") in {(e.child, e.parent) for e in block.ownership.edges}
    assert len(block.custody) == 3


# ----------------------------------------------------------------------------------------------
# passive-only guard
# ----------------------------------------------------------------------------------------------


def test_holehe_blocker_records_a_skip_and_never_runs_the_tool():
    rec = PIRunRecorder()
    blocker = pi_runtime.make_holehe_blocker(rec)
    assert asyncio.run(blocker("a@b.co", "email:a", 1)) is None
    assert rec.entries[0].source == "holehe" and rec.entries[0].status == "skipped"
    assert "not passive" in rec.entries[0].detail


# ----------------------------------------------------------------------------------------------
# orchestrator wiring
# ----------------------------------------------------------------------------------------------


class _FakeCaseStore:
    def __init__(self) -> None:
        self.queries: List[str] = []

    def search_entity_memory(self, query: str, limit: int = 25) -> List[dict]:
        self.queries.append(query)
        return [{"entity_id": "lei:old", "label": query, "case_id": "bh_prior", "seed_query": query,
                 "sighted_at": "2026-02-02"}]

    def correlate_cross_case_entities(self, graph: Any) -> list:
        return []

    def save_case(self, graph: Any, full_result: Any) -> None:
        return None


_AGENT_METHODS = {
    "accountant": ["investigate_gleif_corporate_hierarchy", "investigate_opensanctions", "investigate_sec_edgar",
                   "investigate_nonprofit_990s_and_usaspending", "investigate_aircraft_adsb"],
    "journalist": ["investigate_news_and_narrative", "investigate_court_dockets", "investigate_wikipedia_revisions",
                   "investigate_openalex_academic_and_grants", "investigate_hackernews_archive",
                   "investigate_wayback_ghost_edits"],
    "onchain": ["investigate_dexscreener_tokens"],
    "osint": ["investigate_identity_and_handle", "investigate_credential_combo", "investigate_email_pivots",
              "investigate_domain_infrastructure"],
    "pi_sources": ["investigate_companies_house_psc", "screen_canadian_sanctions", "screen_ofac_sdn",
                   "screen_un_consolidated", "screen_uk_sanctions_list", "investigate_cfpb_complaints",
                   "investigate_wikidata_entity"],
}


def _orchestrator(engagement: Optional[PIEngagement], **kw: Any) -> BunnyholeOrchestrator:
    orch = BunnyholeOrchestrator(
        "Acme Holdings Ltd", max_depth=1, profile=InvestigatorProfile(persona=Persona.PRIVATE_INVESTIGATOR),
        **({"engagement": engagement} if engagement is not None else {}), **kw,
    )
    orch.case_store = _FakeCaseStore()
    for agent_name, methods in _AGENT_METHODS.items():
        agent = getattr(orch, agent_name, None)
        if agent is None:
            continue
        for method in methods:
            setattr(agent, method, AsyncMock(return_value=None))
    orch.synthesizer.synthesize_investigation = AsyncMock(return_value={})
    orch.council.run_full_council = AsyncMock(return_value={})
    return orch


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


def test_without_an_engagement_credentials_are_untouched():
    from bunnyhole.engine.intake import CaseIntakePacket

    orch = _orchestrator(None)
    packet = CaseIntakePacket(organizations=["Acme Holdings Ltd"], credentials=[CREDENTIAL])
    result = asyncio.run(orch.run_intake_investigation(packet))
    assert result["intake_packet"]["credentials"] == [CREDENTIAL]
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


# ----------------------------------------------------------------------------------------------
# U1: identity resolution in the live run (notes only; nodes are never merged)
# ----------------------------------------------------------------------------------------------


def _person(node_id: str, label: str, attrs: Optional[dict] = None, tool: str = "opensanctions_yente",
            receipts: Optional[list] = None) -> Dict[str, Any]:
    return _nd(node_id, "Person", label=label, receipts=receipts if receipts is not None else
               [_rc(tool, f"https://src/{node_id}")], attrs=attrs or {})


def _block(nodes: list, *, subject_is_person: bool = True, selectors: Optional[dict] = None, **kw: Any) -> PIBlock:
    case_type = kw.pop("case_type", CaseType.BACKGROUND)
    eng = kw.pop("engagement", None) or PIEngagement.build(
        case_type, "Vet a counterparty before signing a supply contract", subject_is_person=subject_is_person,
        purpose_category="counterparty_due_diligence", matter_ref="MSA-2026-114",
    )
    graph_dict = {"nodes": nodes, "edges": kw.pop("edges", []), "timeline": kw.pop("timeline", [])}
    return assemble_pi_block(
        eng, graph_dict, kw.pop("source_log", []), selectors=selectors or {},
        ownership_links=kw.pop("ownership_links", []), now_iso=NOW, **kw,
    )


ANCHORED = {"names": ["John Smith"], "emails": ["js@acme.io"]}


def test_same_name_records_without_anchors_are_not_established_as_one_person():
    nodes = [
        _person("sanction:os1", "John Smith", {"caption": "John Smith", "countries": ["RU"]}),
        _person("sanction:ca1", "⛔ John Smith", {"country": "Canada", "date_of_birth_or_build": ""},
                tool="gac_sema_sanctions"),
    ]
    notes = _block(nodes, selectors=ANCHORED).identity_notes
    joined = "\n".join(notes)
    assert "2 records named 'John Smith' are NOT established as one person" in joined
    assert "name only" in joined and "no corroborating anchor" in joined
    assert "subject not anchored" not in joined  # name + email: two anchors


def test_records_sharing_birth_year_and_address_are_reported_probable_with_their_anchors():
    nodes = [
        _person("sanction:os1", "John Smith", {"date_of_birth_or_build": "1970-03-02", "address": "1 Main St, Leeds"}),
        _person("psc:uk:1:john", "Mr John SMITH", {"birth_year": 1970, "registered_address": "1 Main Street, Leeds"},
                tool="companies_house_psc"),
    ]
    notes = _block(nodes, selectors=ANCHORED).identity_notes
    joined = "\n".join(notes)
    assert "probable same person" in joined
    assert "dob_year" in joined and "address" in joined
    assert "NOT established" not in joined


def test_conflicting_birth_years_are_reported_different_with_the_disqualifier():
    nodes = [
        _person("sanction:os1", "John Smith", {"date_of_birth_or_build": "1950-01-01"}),
        _person("sanction:ca1", "John Smith", {"date_of_birth_or_build": "1990"}, tool="gac_sema_sanctions"),
    ]
    joined = "\n".join(_block(nodes, selectors=ANCHORED).identity_notes)
    assert "NOT established as one person" in joined
    assert "different" in joined and "birth years differ by 40" in joined


def test_countries_that_differ_are_mentioned_but_never_treated_as_an_anchor():
    nodes = [
        _person("sanction:os1", "John Smith", {"countries": ["RU"]}),
        _person("sanction:ca1", "John Smith", {"countries": ["CA"]}, tool="gac_sema_sanctions"),
    ]
    joined = "\n".join(_block(nodes, selectors=ANCHORED).identity_notes)
    assert "NOT established" in joined and "countries differ" in joined and "RU" in joined and "CA" in joined


def test_name_variants_are_grouped_but_different_names_are_not():
    nodes = [
        _person("a", "Robert Jones", {}),
        _person("b", "Bob Jones", {}),
        _person("c", "Alice Walker", {}),
    ]
    joined = "\n".join(_block(nodes, selectors=ANCHORED).identity_notes)
    assert "Robert Jones" in joined and "Bob Jones" in joined and "NOT established" in joined
    assert "Alice Walker" not in joined


def test_only_person_nodes_are_considered_and_the_locked_profile_bundle_is_skipped():
    nodes = [
        _nd("co:1", "Organization", label="John Smith", receipts=[_rc("gleif", "https://g/1")]),
        _nd("co:2", "Organization", label="John Smith", receipts=[_rc("sec", "https://g/2")]),
        _person("profile:locked_target_root", "\U0001f512 Target Profile: John Smith", {}, tool="bunnyhole_intake"),
        _person("a", "John Smith", {}),
    ]
    nodes[2]["risk_flags"] = ["USER_CONFIRMED_TARGET_BUNDLE"]
    assert _block(nodes, selectors=ANCHORED).identity_notes == []


def test_the_subject_record_is_compared_with_listing_records_of_the_same_name():
    seed = _person("seed:john", "John Smith", {}, receipts=[_rc("bunnyhole_case_director", "seed://x")])
    listed = _person("sanction:os1", "John Smith", {"countries": ["RU"]})
    selectors = {"names": ["John Smith"], "emails": ["js@acme.io"]}
    joined = "\n".join(_block([seed, listed], selectors=selectors).identity_notes)
    assert "2 records named 'John Smith' are NOT established as one person" in joined


@pytest.mark.parametrize(
    "selectors,expected",
    [({"names": ["John Smith"]}, True), ({}, True), ({"emails": ["js@acme.io"]}, True),
     ({"names": ["John Smith"], "emails": ["js@acme.io"]}, False),
     ({"names": ["John Smith"], "usernames": ["jsmith"]}, False)],
)
def test_person_subject_with_fewer_than_two_anchors_gets_the_standing_note(selectors: dict, expected: bool):
    notes = _block([], selectors=selectors).identity_notes
    assert any(n.startswith("subject not anchored: name alone is not an identity") for n in notes) is expected


def test_entity_subject_never_gets_the_not_anchored_note():
    assert _block([], subject_is_person=False, selectors={"organizations": ["Acme Ltd"]}).identity_notes == []


def test_identity_notes_are_deterministic_and_do_not_mutate_the_nodes():
    import copy

    nodes = [
        _person("a", "John Smith", {"date_of_birth_or_build": "1970"}),
        _person("b", "John Smith", {"date_of_birth_or_build": "1990"}),
        _person("c", "John Smith", {"date_of_birth_or_build": "1970"}),
    ]
    before = copy.deepcopy(nodes)
    first = _block(nodes, selectors=ANCHORED)
    second = _block(nodes, selectors=ANCHORED)
    assert first.identity_notes == second.identity_notes and first.identity_notes
    assert nodes == before
    assert len(first.findings) == 3  # graph nodes are never merged


def test_identity_notes_are_bounded():
    nodes = [_person(f"p{i}", f"Person{i} Smith", {}) for i in range(20)]
    nodes += [_person(f"q{i}", f"Person{i} Smith", {}) for i in range(20)]
    assert len(_block(nodes, selectors=ANCHORED).identity_notes) <= pi_runtime.MAX_IDENTITY_NOTES


# ----------------------------------------------------------------------------------------------
# U2: playbook progress and escalation triggers
# ----------------------------------------------------------------------------------------------


def _log(*rows: tuple) -> List[SourceLogEntry]:
    return [SourceLogEntry(source=s, target="x", status=st, detail=d, at_utc=NOW) for s, st, d in rows]


def _playbook(*steps: tuple, escalate: Optional[list] = None, keys: Optional[dict] = None):
    from bunnyhole.engine.pi_reference import Playbook, PlaybookStep

    return Playbook(
        case_type=CaseType.DUE_DILIGENCE, objective="o", done_when="exactly this, verbatim.",
        steps=[PlaybookStep(order=i, action=a, sources=list(src), yield_level="high", cost=cost)
               for i, (a, src, cost) in enumerate(steps, start=1)],
        escalate_when=escalate or [], pitfalls=[], typical_hypotheses=[], escalate_keys=keys or {},
    )


def test_playbook_source_map_only_names_real_catalog_sources_and_real_recorder_sources():
    from bunnyhole.engine.pi_reference import SOURCES

    catalog = {s.name for s in SOURCES}
    # wikidata/wikipedia/holehe/breach sources are recorded but deliberately absent from SOURCE_CLASS_MAP
    recorded = set(SOURCE_CLASS_MAP) | {"wikidata", "wikipedia", "holehe", "hudsonrock", "leakcheck", "emailrep"}
    assert pi_runtime.PLAYBOOK_SOURCE_MAP
    for name, recorder_names in pi_runtime.PLAYBOOK_SOURCE_MAP.items():
        assert name in catalog, name
        assert recorder_names and set(recorder_names) <= recorded, name


def test_progress_done_partial_not_run_handoff_and_manual_steps():
    pb = _playbook(
        ("both ran", ["Wikidata", "CFPB Consumer Complaints"], "free"),
        ("one ran", ["Wikidata", "SEC EDGAR"], "free"),
        ("none ran", ["GLEIF LEI Search"], "free"),
        ("skipped only", ["OpenSanctions"], "free"),
        ("unmapped only", ["PACER Case Locator"], "free"),
        ("mapped ran + unmapped", ["Wikidata", "PACER Case Locator"], "free"),
        ("licensed layer", ["licensed credit-header database"], "handoff"),
        ("manual", [], "free"),
    )
    log = _log(("wikidata", "negative", "ran"), ("cfpb_complaints", "hit", "1 node"),
               ("opensanctions", "skipped", "no key"), ("sec_edgar", "error", "HTTP 500 from sec.gov"))
    progress = pi_runtime.playbook_progress_for(pb, log)
    assert [p.status for p in progress] == ["done", "partial", "not_run", "not_run", "not_run", "partial", "handoff",
                                            "not_run"]
    assert [p.order for p in progress] == list(range(1, 9))
    assert progress[1].action == "one ran" and progress[1].sources == ["Wikidata", "SEC EDGAR"]


def test_progress_evidence_names_what_ran_and_what_was_skipped_or_failed():
    pb = _playbook(("screen", ["Wikidata", "SEC EDGAR", "OpenSanctions", "PACER Case Locator"], "free"))
    log = _log(("wikidata", "negative", "ran"), ("sec_edgar", "error", "HTTP 500 from data.sec.gov"),
               ("opensanctions", "skipped", "no key"))
    evidence = pi_runtime.playbook_progress_for(pb, log)[0].evidence
    assert "ran: Wikidata (negative)" in evidence
    assert "SEC EDGAR" in evidence and "error" in evidence and "HTTP 500 from data.sec.gov" in evidence
    assert "OpenSanctions" in evidence and "skipped" in evidence and "no key" in evidence
    assert "PACER Case Locator" in evidence and "not automated" in evidence


def test_progress_handoff_and_manual_evidence_are_explicit():
    pb = _playbook(("licensed", ["licensed credit-header database"], "handoff"), ("manual", [], "free"))
    handoff, manual = pi_runtime.playbook_progress_for(pb, [])
    assert "licensed" in handoff.evidence.lower() or "counsel" in handoff.evidence.lower()
    assert "no automated source" in manual.evidence


def test_a_source_ran_if_any_of_its_log_entries_is_a_hit_or_negative():
    pb = _playbook(("screen", ["GLEIF LEI Search"], "free"))
    log = _log(("gleif", "skipped", "x"), ("gleif", "negative", "ran"))
    assert pi_runtime.playbook_progress_for(pb, log)[0].status == "done"


def test_assemble_fills_done_when_progress_and_triggers_from_the_case_type_playbook():
    from bunnyhole.engine.pi_reference import playbook_for

    pb = playbook_for(CaseType.DUE_DILIGENCE)
    block = _block([], subject_is_person=False, case_type=CaseType.DUE_DILIGENCE,
                   source_log=_log(("gleif", "negative", "ran")))
    assert block.done_when == pb.done_when
    assert [p.order for p in block.playbook_progress] == [s.order for s in pb.steps]
    assert [t.trigger for t in block.escalation_triggers] == pb.escalate_when
    assert PIBlock.model_validate(block.model_dump(mode="json")) == block  # still valid JSON schema


def _trigger(block: PIBlock, key_text_fragment: str):
    return next(t for t in block.escalation_triggers if key_text_fragment in t.trigger)


def test_unkeyed_triggers_are_not_evaluated_automatically():
    block = _block([], subject_is_person=False, case_type=CaseType.MISSING_PERSON)
    assert block.escalation_triggers and all(not t.fired and t.why == "not evaluated automatically"
                                             for t in block.escalation_triggers)


def test_unresolved_ownership_trigger_fires_only_on_nominee_evidence_and_names_the_nodes():
    # Requirement change 2026-11-09 (third quality pass, R5): an unresolved chain alone is not "ends at a nominee or
    # secrecy jurisdiction". It fires only when a nominee/secrecy flag is present; otherwise it says why it did not.
    nodes = [_nd("lei:orphan"), _nd("co:sub")]
    edges = [_ed("lei:orphan", "ULTIMATE_PARENT_OF", "co:sub")]
    block = _block(nodes, subject_is_person=False, case_type=CaseType.DUE_DILIGENCE, edges=edges)
    trig = _trigger(block, "ownership chain ends")
    assert not trig.fired and "lei:orphan" in trig.why
    assert "ownership walk unresolved (no nominee or secrecy-jurisdiction evidence)" in trig.why
    flagged = [_nd("lei:orphan", flags=["OFFSHORE_SECRECY_JURISDICTION_VG"]), _nd("co:sub")]
    fired = _trigger(_block(flagged, subject_is_person=False, case_type=CaseType.DUE_DILIGENCE, edges=edges),
                     "ownership chain ends")
    assert fired.fired and "lei:orphan" in fired.why and "OFFSHORE_SECRECY_JURISDICTION_VG" in fired.why
    clean = _block([], subject_is_person=False, case_type=CaseType.DUE_DILIGENCE)
    assert not _trigger(clean, "ownership chain ends").fired


def test_sanctions_trigger_fires_on_a_listing_node_or_a_50_percent_block():
    listed = _nd("sanction:x", receipts=[_rc("opensanctions_yente", "https://os/x")], label="Listed Co")
    block = _block([listed], subject_is_person=False, case_type=CaseType.DUE_DILIGENCE)
    trig = _trigger(block, "sanctions hit")
    assert trig.fired and "sanction:x" in trig.why
    pep = _nd("p:1", "Person", label="Pat Official", flags=["POLITICALLY_EXPOSED_PERSON_PEP"])
    assert _trigger(_block([pep], subject_is_person=False, case_type=CaseType.DUE_DILIGENCE), "sanctions hit").fired
    assert not _trigger(_block([], subject_is_person=False, case_type=CaseType.DUE_DILIGENCE), "sanctions hit").fired


def test_50_percent_rule_block_fires_the_sanctions_trigger():
    nodes = [_nd("sanction:p", receipts=[_rc("opensanctions_yente", "https://os/p")]), _nd("co:child")]
    edges = [_ed("sanction:p", "OWNS", "co:child")]
    nodes[0]["attributes"] = {"ownership_pct_midpoint": 60.0}
    block = _block(nodes, subject_is_person=False, case_type=CaseType.DUE_DILIGENCE, edges=edges)
    assert block.ownership.blocked_by_50_rule == ["co:child"]
    trig = _trigger(block, "sanctions hit")
    assert trig.fired and "co:child" in trig.why


def test_custodian_trigger_fires_when_a_custodian_bearing_finding_is_present():
    block = _block([_nd("domain:acme.io", "Domain")], subject_is_person=False, case_type=CaseType.FRAUD_SCREEN)
    trig = _trigger(block, "funds trail")
    assert block.custodians and trig.fired
    assert not _trigger(_block([], subject_is_person=False, case_type=CaseType.FRAUD_SCREEN), "funds trail").fired


def test_no_corroborated_finding_fires_only_after_a_deep_run():
    lead_only = [_nd("lei:1", receipts=[_rc("gleif", "https://g/1")])]
    shallow = _block(lead_only, deep_run=False,
                     engagement=PIEngagement.build(CaseType.LOCATE, "Enforce judgment 24-CV-1 against debtor",
                                                   matter_ref="24-CV-1", purpose_category="judgment_enforcement"))
    deep = _block(lead_only, deep_run=True,
                  engagement=PIEngagement.build(CaseType.LOCATE, "Enforce judgment 24-CV-1 against debtor",
                                                matter_ref="24-CV-1", purpose_category="judgment_enforcement"))
    assert not _trigger(shallow, "confirmed address is needed").fired
    assert "not a deep run" in _trigger(shallow, "confirmed address is needed").why
    assert _trigger(deep, "confirmed address is needed").fired
    probable = [_nd("lei:1", receipts=[_rc("gleif", "https://g/1"), _rc("opencorp", "https://o/1")])]
    ok = _block(probable, deep_run=True, engagement=PIEngagement.build(
        CaseType.LOCATE, "Enforce judgment 24-CV-1 against debtor", matter_ref="24-CV-1",
        purpose_category="judgment_enforcement"))
    assert not _trigger(ok, "confirmed address is needed").fired


def test_contradiction_trigger_fires_on_any_contradiction():
    timeline = [
        {"timestamp": "2020-01-01T00:00:00Z", "title": "Acme incorporated", "description": "", "node_ids": ["co:a"]},
        {"timestamp": "2019-01-01T00:00:00Z", "title": "Contract signed", "description": "", "node_ids": ["co:a"]},
    ]
    eng = PIEngagement.build(
        CaseType.LOCATE, "Enforce judgment 24-CV-1 against debtor", matter_ref="24-CV-1",
        purpose_category="judgment_enforcement",
    )
    block = _block([_nd("co:a")], engagement=eng, timeline=timeline)
    assert _trigger(block, "disagree on the current address").fired
    assert not _trigger(_block([], engagement=eng), "disagree on the current address").fired


def test_identity_trigger_fires_for_an_unanchored_person_subject():
    block = _block([], case_type=CaseType.BACKGROUND, selectors={"names": ["John Smith"]})
    assert _trigger(block, "Identity cannot be resolved").fired
    anchored = _block([], case_type=CaseType.BACKGROUND, selectors=ANCHORED)
    assert not _trigger(anchored, "Identity cannot be resolved").fired
    entity = _block([], subject_is_person=False, case_type=CaseType.BACKGROUND)
    assert not _trigger(entity, "Identity cannot be resolved").fired


def test_orchestrator_result_carries_the_new_pi_fields_and_deep_run_comes_from_the_gear():
    from bunnyhole.engine.models import GearMode

    orch = _orchestrator(_engagement(), gear=GearMode.DEEP)
    result = asyncio.run(orch.run_investigation())
    block = PIBlock.model_validate(result["pi"])
    assert block.done_when and block.playbook_progress and block.escalation_triggers
    assert isinstance(block.identity_notes, list)
    assert orch._pi_deep_run is True
    assert _orchestrator(_engagement(), gear=GearMode.FAST)._pi_deep_run is False
