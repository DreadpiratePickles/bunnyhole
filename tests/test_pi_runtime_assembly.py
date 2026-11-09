"""Tests for PI block assembly (``assemble_pi_block``): findings and freshness, ownership, false-link flags, contradictions, gaps, coverage, falsifiers, custodians, handoff, custody, the envelope and the passive-only guard.

The later quality passes on assembly are in test_pi_runtime_relevance_handoff.py, test_pi_runtime_sanctions_ownership.py and test_pi_runtime_screening_profile.py.

Everything is offline. Graph dicts are hand-built, agents are faked with coroutines or ``AsyncMock``.
"""

# Replaces: test_pi_runtime.py (consolidated 2026-11-09).

from __future__ import annotations

import asyncio
from typing import Any, Dict, List, Optional

from pi_helpers import NOW
from pi_helpers import built_engagement as _engagement
from pi_helpers import edge_dict as _ed
from pi_helpers import make_graph as _graph
from pi_helpers import make_node as _node
from pi_helpers import make_receipt as _receipt
from pi_helpers import node_dict as _nd
from pi_helpers import receipt_dict as _rc

from bunnyhole.engine import pi_runtime
from bunnyhole.engine.models import DomainCategory, GraphEdge, RelationType
from bunnyhole.engine.pi import CaseType, FindingLabel, PIBlock, SourceLogEntry
from bunnyhole.engine.pi_runtime import (
    PIRunRecorder,
    assemble_pi_block,
)

# ----------------------------------------------------------------------------------------------
# helpers
# ----------------------------------------------------------------------------------------------


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
