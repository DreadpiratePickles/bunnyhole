"""Tests for the PI stream ownership walk, OFAC 50% rule and false-link guards (pure; fetcher injected)."""

from __future__ import annotations

import asyncio
import logging
from typing import Dict, List

import pytest

from bunnyhole.engine.pi import OwnershipBlock, OwnershipEdge
from bunnyhole.engine.pi_ubo import (
    HOSTING_PROVIDER_MARKERS,
    REGISTERED_AGENT_ADDRESS_MARKERS,
    OwnerLink,
    apply_50_percent_rule,
    false_link_reason,
    is_registered_agent_address,
    nominee_flags,
    unresolved_node_id,
    walk_ownership,
)


def _entity(pid: str, pct: float | None = 100.0, **kw) -> OwnerLink:
    return OwnerLink(parent_id=pid, parent_name=pid.upper(), pct=pct, is_natural_person=False, **kw)


def _person(pid: str, pct: float | None = 100.0, **kw) -> OwnerLink:
    return OwnerLink(parent_id=pid, parent_name=pid.title(), pct=pct, is_natural_person=True, **kw)


class _Fetcher:
    """Dict-backed async fetcher that records every call. Values may be an Exception to raise."""

    def __init__(self, table: Dict[str, object]) -> None:
        self.table = table
        self.calls: List[str] = []

    async def __call__(self, node_id: str) -> List[OwnerLink]:
        self.calls.append(node_id)
        value = self.table.get(node_id, [])
        if isinstance(value, Exception):
            raise value
        return list(value)  # type: ignore[arg-type]


def _walk(start: str, table: Dict[str, object], **kw) -> tuple[OwnershipBlock, _Fetcher]:
    fetcher = _Fetcher(table)
    return asyncio.run(walk_ownership(start, fetcher, **kw)), fetcher


# ----------------------------------------------------------------------------------------------
# walk_ownership
# ----------------------------------------------------------------------------------------------


def test_walk_stops_at_natural_person():
    table = {"a": [_entity("b", 60.0, source="gleif", as_of="2026-01-01")], "b": [_person("carol", 80.0)]}
    block, fetcher = _walk("a", table)
    assert isinstance(block, OwnershipBlock)
    assert block.levels_walked == 2
    assert {(e.child, e.parent, e.pct) for e in block.edges} == {("a", "b", 60.0), ("b", "carol", 80.0)}
    assert block.unresolved == []
    assert fetcher.calls == ["a", "b"]  # the natural person is never fetched


def test_walk_preserves_edge_source_and_as_of():
    block, _ = _walk("a", {"a": [_person("carol", 25.0, source="companies_house_psc", as_of="2025-06-30")]})
    (edge,) = block.edges
    assert edge.source == "companies_house_psc" and edge.as_of == "2025-06-30"
    assert edge.child == "a" and edge.parent == "carol"


def test_walk_start_without_owners_is_unresolved_and_zero_levels():
    block, fetcher = _walk("a", {})
    assert block.edges == []
    assert block.levels_walked == 0
    assert block.unresolved == ["a"]
    assert fetcher.calls == ["a"]


def test_walk_entity_without_owners_is_unresolved_but_other_branches_continue():
    table = {"a": [_entity("b", 50.0), _entity("c", 50.0)], "b": [], "c": [_person("dave")]}
    block, _ = _walk("a", table)
    assert block.unresolved == ["b"]
    assert any(e.parent == "dave" for e in block.edges)
    assert block.levels_walked == 2


def test_walk_is_breadth_first_by_layer():
    table = {
        "a": [_entity("b"), _entity("c")],
        "b": [_entity("d")],
        "c": [_person("eve")],
        "d": [_person("frank")],
    }
    block, fetcher = _walk("a", table)
    assert fetcher.calls == ["a", "b", "c", "d"]
    assert block.levels_walked == 3


def test_walk_cycle_guard_terminates_and_fetches_each_node_once():
    block, fetcher = _walk("a", {"a": [_entity("b")], "b": [_entity("a")]})
    assert sorted(fetcher.calls) == ["a", "b"]
    assert {(e.child, e.parent) for e in block.edges} == {("a", "b"), ("b", "a")}
    # a closed loop never reaches a natural person: it must be reported, not hidden
    assert block.unresolved, "a circular ownership loop with no natural person must be reported as unresolved"
    assert all("circular" in u for u in block.unresolved)


def test_walk_self_loop_terminates():
    block, fetcher = _walk("a", {"a": [_entity("a")]})
    assert fetcher.calls == ["a"]
    assert block.unresolved


def test_walk_diamond_fetches_shared_parent_once_and_keeps_both_edges():
    table = {
        "a": [_entity("b", 50.0), _entity("c", 50.0)],
        "b": [_entity("d", 100.0)],
        "c": [_entity("d", 100.0)],
        "d": [_person("gina")],
    }
    block, fetcher = _walk("a", table)
    assert fetcher.calls.count("d") == 1
    assert {(e.child, e.parent) for e in block.edges} >= {("b", "d"), ("c", "d"), ("d", "gina")}
    assert block.unresolved == []


def test_walk_duplicate_edges_are_collapsed():
    block, _ = _walk("a", {"a": [_person("carol", 50.0), _person("carol", 50.0)]})
    assert len(block.edges) == 1


def test_walk_caps_at_max_levels_default_five():
    chain = {f"n{i}": [_entity(f"n{i + 1}")] for i in range(0, 9)}
    block, fetcher = _walk("n0", chain)
    assert block.levels_walked == 5
    assert fetcher.calls == ["n0", "n1", "n2", "n3", "n4"]
    # the frontier we did not expand is reported with the reason
    assert any(unresolved_node_id(u) == "n5" and "max_levels" in u for u in block.unresolved)


def test_walk_respects_custom_max_levels():
    chain = {f"n{i}": [_entity(f"n{i + 1}")] for i in range(0, 9)}
    block, fetcher = _walk("n0", chain, max_levels=2)
    assert block.levels_walked == 2
    assert fetcher.calls == ["n0", "n1"]


def test_walk_reaching_person_exactly_at_the_cap_is_resolved():
    chain: Dict[str, object] = {f"n{i}": [_entity(f"n{i + 1}")] for i in range(0, 4)}
    chain["n4"] = [_person("zoe")]
    block, _ = _walk("n0", chain)
    assert block.levels_walked == 5
    assert block.unresolved == []


def test_walk_fetch_exception_becomes_unresolved_with_reason_and_never_raises(caplog: pytest.LogCaptureFixture):
    table = {"a": [_entity("b"), _entity("c")], "b": RuntimeError("registry boom"), "c": [_person("dave")]}
    with caplog.at_level(logging.WARNING):
        block, _ = _walk("a", table)
    (entry,) = block.unresolved
    assert unresolved_node_id(entry) == "b"
    assert "registry boom" in entry and "RuntimeError" in entry
    assert any(e.parent == "dave" for e in block.edges)  # the other branch still completed
    assert any("registry boom" in r.getMessage() for r in caplog.records)  # not swallowed silently


def test_walk_fetch_exception_on_start_node():
    block, _ = _walk("a", {"a": ConnectionError("down")})
    assert block.edges == []
    assert unresolved_node_id(block.unresolved[0]) == "a" and "down" in block.unresolved[0]


def test_unresolved_node_id_strips_reason_suffix():
    assert unresolved_node_id("abc") == "abc"
    assert unresolved_node_id("abc (fetch failed: RuntimeError: x)") == "abc"
    assert unresolved_node_id("lei:123 (max_levels reached)") == "lei:123"


def test_walk_does_not_populate_blocked_by_50_rule():
    block, _ = _walk("a", {"a": [_person("carol")]})
    assert block.blocked_by_50_rule == []


def test_walk_with_zero_max_levels_expands_nothing():
    block, fetcher = _walk("a", {"a": [_person("carol")]}, max_levels=0)
    assert fetcher.calls == []
    assert block.levels_walked == 0
    assert unresolved_node_id(block.unresolved[0]) == "a"


# ----------------------------------------------------------------------------------------------
# apply_50_percent_rule
# ----------------------------------------------------------------------------------------------


def _edge(child: str, parent: str, pct: float | None) -> OwnershipEdge:
    return OwnershipEdge(child=child, parent=parent, pct=pct, source="test")


def test_direct_majority_is_blocked():
    assert apply_50_percent_rule([_edge("co", "bad", 60.0)], {"bad"}) == ["co"]


def test_exactly_fifty_is_blocked():
    assert apply_50_percent_rule([_edge("co", "bad", 50.0)], {"bad"}) == ["co"]


def test_just_under_fifty_is_not_blocked():
    assert apply_50_percent_rule([_edge("co", "bad", 49.9)], {"bad"}) == []


def test_aggregate_of_two_listed_owners_is_blocked():
    edges = [_edge("co", "bad1", 30.0), _edge("co", "bad2", 25.0)]
    assert apply_50_percent_rule(edges, {"bad1", "bad2"}) == ["co"]


def test_aggregate_float_edge_case_sums_to_fifty():
    edges = [_edge("co", "bad1", 33.3), _edge("co", "bad2", 16.7)]
    assert apply_50_percent_rule(edges, {"bad1", "bad2"}) == ["co"]


def test_indirect_fixpoint_blocked_entity_blocks_its_subsidiary():
    # bad -50%-> mid -60%-> sub : mid is blocked, then sub is blocked through mid.
    edges = [_edge("sub", "mid", 60.0), _edge("mid", "bad", 50.0)]  # reverse order on purpose
    assert apply_50_percent_rule(edges, {"bad"}) == ["mid", "sub"]


def test_indirect_chain_of_three_levels():
    edges = [_edge("d", "c", 100.0), _edge("c", "b", 100.0), _edge("b", "a", 100.0)]
    assert apply_50_percent_rule(edges, {"a"}) == ["b", "c", "d"]


def test_indirect_chain_breaks_when_a_link_is_under_fifty():
    edges = [_edge("sub", "mid", 60.0), _edge("mid", "bad", 49.0)]
    assert apply_50_percent_rule(edges, {"bad"}) == []


def test_blocked_by_rule_owner_aggregates_with_listed_owner():
    edges = [_edge("mid", "bad", 50.0), _edge("sub", "bad", 30.0), _edge("sub", "mid", 30.0)]
    assert apply_50_percent_rule(edges, {"bad"}) == ["mid", "sub"]


def test_pct_none_counts_as_zero():
    assert apply_50_percent_rule([_edge("co", "bad", None)], {"bad"}) == []
    edges = [_edge("co", "bad1", None), _edge("co", "bad2", 50.0)]
    assert apply_50_percent_rule(edges, {"bad1", "bad2"}) == ["co"]


def test_listed_ids_are_not_returned_even_when_owned_by_other_listed_ids():
    edges = [_edge("listed2", "listed1", 100.0)]
    assert apply_50_percent_rule(edges, {"listed1", "listed2"}) == []


def test_unlisted_owner_never_blocks():
    assert apply_50_percent_rule([_edge("co", "clean", 100.0)], {"bad"}) == []


def test_cycles_terminate():
    edges = [_edge("a", "b", 100.0), _edge("b", "a", 100.0)]
    assert apply_50_percent_rule(edges, set()) == []
    assert apply_50_percent_rule(edges, {"a"}) == ["b"]


def test_duplicate_edges_from_two_sources_are_not_double_counted():
    edges = [_edge("co", "bad", 30.0), OwnershipEdge(child="co", parent="bad", pct=30.0, source="other")]
    assert apply_50_percent_rule(edges, {"bad"}) == []


def test_result_is_sorted_and_input_order_independent():
    edges = [_edge("zz", "bad", 100.0), _edge("aa", "bad", 100.0), _edge("mm", "bad", 100.0)]
    assert apply_50_percent_rule(edges, {"bad"}) == ["aa", "mm", "zz"]
    assert apply_50_percent_rule(list(reversed(edges)), {"bad"}) == ["aa", "mm", "zz"]


def test_empty_inputs():
    assert apply_50_percent_rule([], {"bad"}) == []
    assert apply_50_percent_rule([_edge("co", "bad", 100.0)], set()) == []


def test_input_edges_are_not_mutated():
    edges = [_edge("co", "bad", 60.0)]
    snapshot = [e.model_copy() for e in edges]
    apply_50_percent_rule(edges, {"bad"})
    assert edges == snapshot


# ----------------------------------------------------------------------------------------------
# Registered agents, nominees, false links
# ----------------------------------------------------------------------------------------------


def test_marker_table_has_real_known_addresses_and_is_lowercase():
    assert len(REGISTERED_AGENT_ADDRESS_MARKERS) >= 15
    assert all(m == m.lower() for m in REGISTERED_AGENT_ADDRESS_MARKERS)
    for fragment in ("1209 orange st", "251 little falls", "2711 centerville", "8 the green", "1000 brickell"):
        assert fragment in REGISTERED_AGENT_ADDRESS_MARKERS


@pytest.mark.parametrize(
    "address",
    [
        "1209 Orange Street, Wilmington, DE 19801",
        "251 Little Falls Drive, Wilmington, Delaware",
        "2711 Centerville Road, Suite 400, Wilmington",
        "8 The Green, Suite A, Dover, DE 19901",
        "1000 Brickell Ave Suite 715, Miami, FL",
        "C/O National Registered Agents, Inc.",
        "Acme Holdings c/o Corporate Services Ltd",
        "The Registered Agent LLC, PO Box 1",
        "  1209   ORANGE   ST.  ",
    ],
)
def test_registered_agent_addresses_detected(address: str):
    assert is_registered_agent_address(address)


@pytest.mark.parametrize(
    "address",
    ["742 Evergreen Terrace, Springfield", "18 The Green, Richmond", "", "   ", "1 Main St, Exampleville"],
)
def test_ordinary_addresses_not_flagged(address: str):
    assert not is_registered_agent_address(address)


def test_nominee_flags_threshold_and_order():
    flags = nominee_flags({"Alice": 3, "Bob Nominee": 25, "Carl Director": 300, "Dee": 24})
    assert [f["officer"] for f in flags] == ["Carl Director", "Bob Nominee"]
    assert flags[0]["entities"] == 300
    assert "300" in flags[0]["reason"]
    assert set(flags[0]) == {"officer", "entities", "reason"}


def test_nominee_flags_custom_threshold_and_empty():
    assert [f["officer"] for f in nominee_flags({"A": 5, "B": 4}, threshold=5)] == ["A"]
    assert nominee_flags({}) == []


def test_hosting_markers_cover_common_providers():
    for provider in ("cloudflare", "godaddy", "amazon", "namecheap", "wix", "squarespace"):
        assert provider in HOSTING_PROVIDER_MARKERS


def test_false_link_registered_agent_address():
    reason = false_link_reason("address", "1209 Orange St, Wilmington DE")
    assert reason and "registered" in reason.lower()


def test_false_link_real_address_is_a_candidate():
    assert false_link_reason("address", "742 Evergreen Terrace, Springfield") is None


def test_false_link_address_shared_by_many_entities():
    assert false_link_reason("address", "742 Evergreen Terrace, Springfield", entity_count=60)
    assert false_link_reason("address", "742 Evergreen Terrace, Springfield", entity_count=2) is None


def test_false_link_officer_by_frequency():
    assert false_link_reason("officer", "Carl Director", entity_count=40)
    assert false_link_reason("officer", "Carl Director", entity_count=3) is None
    assert false_link_reason("officer", "Carl Director") is None


def test_false_link_nominee_named_officer():
    assert false_link_reason("officer", "Apex Nominee Directors Ltd")


@pytest.mark.parametrize("value", ["Cloudflare, Inc.", "AMAZON-02", "GoDaddy.com, LLC", "Namecheap Inc", "Wix.com"])
@pytest.mark.parametrize("kind", ["ip", "hosting"])
def test_false_link_shared_hosting(kind: str, value: str):
    reason = false_link_reason(kind, value)
    assert reason and "hosting" in reason.lower()


def test_false_link_ordinary_hosting_value_is_a_candidate():
    assert false_link_reason("hosting", "Acme Dedicated Servers Ltd") is None
    assert false_link_reason("hosting", "Lawson Networks") is None  # "aws" inside a word is not AWS


def test_false_link_ip_shared_by_many_domains():
    assert false_link_reason("ip", "203.0.113.5", entity_count=500)
    assert false_link_reason("ip", "203.0.113.5") is None
    assert false_link_reason("ip", "203.0.113.5", entity_count=2) is None


def test_false_link_common_name():
    assert false_link_reason("name", "John Smith")
    assert false_link_reason("name", "Maria Garcia")
    assert false_link_reason("name", "Zbigniew Wojciechowski") is None


def test_false_link_kind_is_case_insensitive_and_unknown_kind_is_a_candidate():
    assert false_link_reason("ADDRESS", "1209 Orange St")
    assert false_link_reason("favourite_colour", "blue") is None
