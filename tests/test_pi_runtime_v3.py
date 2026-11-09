"""Third quality pass on the PI runtime: profile picker, soft sanctions matches, 50% rule, nominee trigger, noise.

Offline. Graph dicts are hand-built (``graph.to_dict()`` shape). Engagements are built directly (the purpose gates are
covered by their own tests). The examples are what live Bombardier, Rosneft and Boeing reports showed.
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional

import pytest

from bunnyhole.engine.pi import CaseType, EntityProfile, Finding, PIBlock, PIEngagement, SourceLogEntry
from bunnyhole.engine.pi_analysis import find_gaps
from bunnyhole.engine.pi_escalation import FIFTY_RULE_NOT_EVALUABLE
from bunnyhole.engine.pi_reference import SOURCES
from bunnyhole.engine.pi_runtime import assemble_pi_block

NOW = "2026-11-09T00:00:00+00:00"
CYRILLIC_ROSNEFT = 'публичное акционерное общество "Нефтяная компания "Роснефть"'
NOT_EVALUABLE = "50%-rule: not evaluable (ownership percentages unknown)"


# ---------------------------------------------------------------- builders


def _rc(tool: str, url: str = "", snippet: str = "") -> Dict[str, Any]:
    return {
        "receipt_id": f"rcpt_{tool}_{abs(hash((tool, url, snippet))) % 100_000}",
        "tool": tool,
        "source_url": url or f"https://example.test/{tool}",
        "sha256_proof": "ab" * 32,
        "timestamp": NOW,
        "extracted_fact": "f",
        "raw_snippet": snippet,
    }


def _nd(node_id: str, label: str = "", etype: str = "Organization", tool: str = "", attrs: Optional[dict] = None,
        flags: Optional[list] = None, snippet: str = "") -> Dict[str, Any]:
    return {
        "id": node_id,
        "label": label or node_id,
        "entity_type": etype,
        "receipts": [_rc(tool, snippet=snippet)] if tool else [],
        "attributes": attrs or {},
        "risk_flags": flags or [],
    }


def _ed(src: str, rel: str, dst: str) -> Dict[str, Any]:
    return {"id": f"e_{src}_{rel}_{dst}", "source_id": src, "target_id": dst, "relation": rel, "receipts": [],
            "event_date": None}


def _eng(**kw: Any) -> PIEngagement:
    return PIEngagement(engagement_id="pi_0123456789", case_type=CaseType.DUE_DILIGENCE,
                        purpose="Vet a counterparty before signing a supply contract",
                        subject_is_person=False, created_at_utc=NOW, **kw)


def _log(*rows: tuple) -> List[SourceLogEntry]:
    return [SourceLogEntry(source=s, target="x", status=st, detail=d, at_utc=NOW) for s, st, d in rows]


def _assemble(nodes: list, edges: Optional[list] = None, *, seed: str = "Rosneft", log: Optional[list] = None,
              timeline: Optional[list] = None, **kw: Any) -> PIBlock:
    graph = {"seed_query": seed, "nodes": nodes, "edges": edges or [], "timeline": timeline or []}
    return assemble_pi_block(_eng(), graph, log or [], now_iso=NOW, **kw)


def _by_id(block: PIBlock) -> Dict[str, Finding]:
    return {f.node_id: f for f in block.findings}


def _trigger(block: PIBlock, fragment: str) -> Any:
    return next(t for t in block.escalation_triggers if fragment in t.trigger)


def _anchor(label: str = "Rosneft", node_id: str = "company:rosneft") -> Dict[str, Any]:
    return _nd(node_id, f"🎯 {label}", tool="bunnyhole_case_director")


# ---------------------------------------------------------------- R2: the entity profile picker


def test_profile_is_found_for_a_cyrillic_registry_record_of_the_subject():
    nodes = [
        _anchor(),
        _nd("lei:253400JT3MQWNDKMJE44", f"👑 {CYRILLIC_ROSNEFT} (RU)", tool="gleif_level2_ultimate_parent",
            attrs={"lei": "253400JT3MQWNDKMJE44", "legal_name": CYRILLIC_ROSNEFT, "jurisdiction": "RU"}),
    ]
    block = _assemble(nodes)
    assert _by_id(block)["lei:253400JT3MQWNDKMJE44"].relevance == "subject"
    assert isinstance(block.entity_profile, EntityProfile)
    assert block.entity_profile.lei == "253400JT3MQWNDKMJE44"
    assert block.entity_profile.jurisdiction == "RU"


def test_profile_never_picks_a_possible_collision_node():
    nodes = [
        _anchor(),
        _nd("lei:BANK0000000000000001", "Rosneft Bank (RU)", tool="gleif_level1_level2_api",
            attrs={"lei": "BANK0000000000000001", "status": "ACTIVE", "jurisdiction": "RU",
                   "registered_address": "1 Bank Street"}),
    ]
    block = _assemble(nodes)
    assert _by_id(block)["lei:BANK0000000000000001"].relevance != "subject"
    assert block.entity_profile is None


def test_profile_prefers_the_subject_registry_node_over_a_related_one_with_more_fields():
    nodes = [
        _anchor(),
        _nd("lei:SUB00000000000000001", "Rosneft Deutschland GmbH (DE)", tool="gleif_level1_level2_api",
            attrs={"lei": "SUB00000000000000001", "status": "ACTIVE", "jurisdiction": "DE",
                   "registered_address": "Behrenstrasse 18"}),
        _nd("lei:253400JT3MQWNDKMJE44", "Rosneft PJSC", tool="gleif_level2_ultimate_parent",
            attrs={"lei": "253400JT3MQWNDKMJE44", "legal_name": "Rosneft PJSC"}),
    ]
    profile = _assemble(nodes).entity_profile
    assert profile is not None and profile.lei == "253400JT3MQWNDKMJE44"


def test_a_registry_node_with_the_subjects_lei_attribute_is_the_subject_whatever_its_name():
    nodes = [
        _anchor(label="253400JT3MQWNDKMJE44"),
        _nd("lei:253400JT3MQWNDKMJE44", "Completely Different Local Name", tool="gleif_level1_level2_api",
            attrs={"lei": "253400JT3MQWNDKMJE44", "status": "ACTIVE", "jurisdiction": "RU"}),
    ]
    block = _assemble(nodes, seed="", subject="253400JT3MQWNDKMJE44")
    assert _by_id(block)["lei:253400JT3MQWNDKMJE44"].relevance == "subject"
    assert block.entity_profile is not None and block.entity_profile.lei == "253400JT3MQWNDKMJE44"


def test_a_registry_node_carrying_the_subject_as_an_alias_is_the_subject():
    nodes = [
        _anchor(),
        _nd("lei:ALIAS000000000000001", "Public Oil Major", tool="gleif_level1_level2_api",
            attrs={"lei": "ALIAS000000000000001", "aliases": ["Rosneft"], "status": "ACTIVE"}),
    ]
    assert _assemble(nodes).entity_profile is not None


# ---------------------------------------------------------------- R3 / R4: soft sanctions matches inside the graph


def _rosneft_sanctions_graph(child_pct: Optional[float] = 60.0) -> list:
    parent_attrs: Dict[str, Any] = {"lei": "TRADING00000000000001", "legal_name": "Rosneft Trading S.A."}
    if child_pct is not None:
        parent_attrs["ownership_pct_midpoint"] = child_pct
    return [
        _anchor(),
        _nd("sanction:ofac:18299", "⛔ ROSNEFT TRADING S.A.", tool="ofac_sdn"),
        _nd("lei:TRADING00000000000001", "🏛️ Rosneft Trading S.A. (CH)", tool="gleif_level1_level2_api",
            attrs=parent_attrs),
        _nd("lei:CHILD000000000000001", "Swiss Logistics AG (CH)", tool="gleif_level1_level2_api",
            attrs={"lei": "CHILD000000000000001"}),
    ]


def test_a_graph_entity_matching_a_hit_name_is_listed_soft_and_the_50_rule_can_fire():
    edges = [_ed("lei:TRADING00000000000001", "OWNS", "lei:CHILD000000000000001")]
    block = _assemble(_rosneft_sanctions_graph(60.0), edges, log=_log(("ofac_sdn", "hit", "")))
    assert block.ownership.blocked_by_50_rule == ["lei:CHILD000000000000001"]
    trig = _trigger(block, "sanctions hit")
    assert trig.fired
    assert "lei:TRADING00000000000001" in trig.why and "50% rule block" in trig.why


def test_the_soft_listed_node_is_tagged_in_findings_identity_notes_and_the_sanctions_block():
    block = _assemble(_rosneft_sanctions_graph(), log=_log(("ofac_sdn", "hit", "")))
    finding = _by_id(block)["lei:TRADING00000000000001"]
    assert "matches a sanctions-list entry (soft)" in finding.relevance_reason
    assert any("matches a sanctions-list entry (soft)" in n and "Rosneft Trading" in n for n in block.identity_notes)
    graph_hits = [h for h in block.sanctions.hits if h.get("graph_match")]
    assert [h["node_id"] for h in graph_hits] == ["lei:TRADING00000000000001"]
    assert graph_hits[0]["list"] == "OFAC SDN"
    primary = [h for h in block.sanctions.hits if not h.get("graph_match")]
    assert [h["node_id"] for h in primary] == ["sanction:ofac:18299"]


def test_an_affiliate_or_a_different_line_entity_is_not_soft_listed():
    nodes = _rosneft_sanctions_graph() + [
        _nd("lei:DEU00000000000000001", "Rosneft Deutschland GmbH (DE)", tool="gleif_level1_level2_api"),
        _nd("lei:BANK0000000000000001", "Rosneft Bank (RU)", tool="gleif_level1_level2_api"),
    ]
    block = _assemble(nodes, log=_log(("ofac_sdn", "hit", "")))
    soft = {h["node_id"] for h in block.sanctions.hits if h.get("graph_match")}
    assert soft == {"lei:TRADING00000000000001"}


def test_hit_nodes_the_seed_anchor_and_document_nodes_are_never_soft_listed():
    nodes = _rosneft_sanctions_graph() + [
        _nd("wikidata:Q1", "Wikidata Q1: Rosneft Trading S.A.", tool="wikidata"),
        _nd("article:1", "News: ROSNEFT TRADING S.A. sued", tool="google_news_rss"),
        _nd("sec:1", "SEC Form 6-K: ROSNEFT TRADING S.A.", tool="sec_edgar_efts + edgartools"),
    ]
    block = _assemble(nodes, log=_log(("ofac_sdn", "hit", "")))
    soft = {h["node_id"] for h in block.sanctions.hits if h.get("graph_match")}
    assert soft == {"lei:TRADING00000000000001"}


def test_hit_aliases_from_the_receipt_snippet_are_matched_too():
    nodes = [
        _anchor("Alpha Trading"),
        _nd("sanction:ofac:1", "⛔ Alpha Trading Corp", tool="ofac_sdn",
            snippet="id=1 | name=Alpha Trading Corp | aliases=['Alfa Export S.A.', 'Cyrillic'] | Entity"),
        _nd("lei:ALFA0000000000000001", "Alfa Export S.A. (CH)", tool="gleif_level1_level2_api"),
    ]
    block = _assemble(nodes, seed="Alpha Trading", log=_log(("ofac_sdn", "hit", "")))
    assert {h["node_id"] for h in block.sanctions.hits if h.get("graph_match")} == {"lei:ALFA0000000000000001"}


def test_an_ofac_node_counts_as_listed_for_the_trigger_even_when_it_is_only_related():
    nodes = [_anchor(), _nd("sanction:ofac:18299", "⛔ ROSNEFT TRADING S.A.", tool="ofac_sdn")]
    block = _assemble(nodes, log=_log(("ofac_sdn", "hit", "")))
    assert _by_id(block)["sanction:ofac:18299"].relevance == "related"
    trig = _trigger(block, "sanctions hit")
    assert trig.fired and "sanction:ofac:18299" in trig.why


def test_no_soft_match_without_any_hit():
    block = _assemble(_rosneft_sanctions_graph()[:1] + _rosneft_sanctions_graph()[2:],
                      log=_log(("ofac_sdn", "negative", "")))
    assert not [h for h in block.sanctions.hits if h.get("graph_match")]


# ---------------------------------------------------------------- R3: the 50% rule without percentages


def _unknown_pct_block() -> PIBlock:
    nodes = [
        _anchor(),
        _nd("lei:PARENT0000000000001", "Rosneft PJSC", tool="gleif_level1_level2_api"),
        _nd("lei:CHILD000000000000001", "Rosneft Deutschland GmbH", tool="gleif_level1_level2_api"),
    ]
    edges = [_ed("lei:PARENT0000000000001", "ULTIMATE_PARENT_OF", "lei:CHILD000000000000001")]
    return _assemble(nodes, edges, log=_log(("ofac_sdn", "negative", "")))


def test_unknown_percentages_are_said_in_the_escalation_text_not_none():
    block = _unknown_pct_block()
    assert block.ownership.edges and all(e.pct is None for e in block.ownership.edges)
    trig = _trigger(block, "sanctions hit")
    assert NOT_EVALUABLE in trig.why
    assert FIFTY_RULE_NOT_EVALUABLE == NOT_EVALUABLE


def test_known_percentages_do_not_claim_the_rule_is_unevaluable():
    nodes = [
        _anchor(),
        _nd("lei:PARENT0000000000001", "Rosneft PJSC", tool="gleif_level1_level2_api",
            attrs={"ownership_pct_midpoint": 30.0}),
        _nd("lei:CHILD000000000000001", "Rosneft Deutschland GmbH", tool="gleif_level1_level2_api"),
    ]
    block = _assemble(nodes, [_ed("lei:PARENT0000000000001", "OWNS", "lei:CHILD000000000000001")],
                      log=_log(("ofac_sdn", "negative", "")))
    assert NOT_EVALUABLE not in _trigger(block, "sanctions hit").why


# ---------------------------------------------------------------- R5: nominee / secrecy trigger needs evidence


def _chain(parent: Dict[str, Any], extra: Optional[list] = None, extra_edges: Optional[list] = None) -> PIBlock:
    nodes = [_anchor("Acme"), parent, _nd("co:sub", "Acme Sub", tool="gleif_level1_level2_api")] + (extra or [])
    edges = [_ed(parent["id"], "ULTIMATE_PARENT_OF", "co:sub")] + (extra_edges or [])
    return _assemble(nodes, edges, seed="Acme")


def _parent(**kw: Any) -> Dict[str, Any]:
    return _nd("lei:ACMEPARENT", "Acme Holdings Corp", tool="gleif_level1_level2_api", **kw)


def test_a_listed_company_chain_without_nominee_evidence_does_not_fire():
    block = _chain(_nd("cik:777", "Acme Corp", tool="sec_edgar_efts + edgartools", attrs={"ticker": "ACME"}))
    trig = _trigger(block, "ownership chain ends")
    assert not trig.fired


def test_an_unresolved_chain_without_nominee_evidence_does_not_fire_and_says_why():
    trig = _trigger(_chain(_parent()), "ownership chain ends")
    assert not trig.fired
    assert "ownership walk unresolved (no nominee or secrecy-jurisdiction evidence)" in trig.why
    assert "lei:ACMEPARENT" in trig.why


def test_a_secrecy_jurisdiction_on_an_ownership_parent_fires_the_trigger():
    trig = _trigger(_chain(_parent(attrs={"jurisdiction": "VG"})), "ownership chain ends")
    assert trig.fired and "VG" in trig.why and "lei:ACMEPARENT" in trig.why


def test_a_secrecy_risk_flag_on_the_chain_fires_the_trigger():
    trig = _trigger(_chain(_parent(flags=["OFFSHORE_SECRECY_JURISDICTION_KY"])), "ownership chain ends")
    assert trig.fired and "OFFSHORE_SECRECY_JURISDICTION_KY" in trig.why


def test_a_nominee_false_link_flag_fires_the_trigger():
    nominee = _nd("person:nom", "Global Nominee Services", etype="Person", tool="uk_psc")
    block = _chain(_parent(), extra=[nominee], extra_edges=[_ed("person:nom", "DIRECTOR_OF", "company:rosneft")])
    assert any("nominee" in f["reason"] for f in block.false_link_flags)
    trig = _trigger(block, "ownership chain ends")
    assert trig.fired and "nominee" in trig.why


def test_the_secrecy_codes_match_the_accountant_offshore_list():
    from bunnyhole.agents.accountant import OFFSHORE_HAVEN_CODES
    from bunnyhole.engine.pi_runtime import SECRECY_JURISDICTION_CODES

    assert set(SECRECY_JURISDICTION_CODES) == set(OFFSHORE_HAVEN_CODES)


# ---------------------------------------------------------------- R6: gaps and registered-agent noise


def _event(timestamp: str, title: str, node_ids: list) -> Dict[str, Any]:
    return {"timestamp": timestamp, "title": title, "description": "", "node_ids": node_ids}


def test_gaps_are_not_driven_by_filings_of_other_entities_and_use_labels_not_ids():
    nodes = [
        _anchor("Bombardier Inc", "company:bombardier_inc"),
        _nd("sec:other1", "SEC Form 10-K: PINNACLE AIRLINES CORP (CIK 0001166291)", tool="sec_edgar_efts + edgartools"),
        _nd("sec:other2", "SEC Form 10-K: ALASKA AIR GROUP INC (CIK 0000766421)", tool="sec_edgar_efts + edgartools"),
        _nd("lei:SUBJ", "BOMBARDIER INC. (CA-QC)", tool="gleif_level1_level2_api"),
    ]
    timeline = [
        _event("2008-03-17T00:00:00Z", "SEC Form 10-K: PINNACLE AIRLINES", ["company:bombardier_inc", "sec:other1"]),
        _event("2026-09-07T00:00:00Z", "SEC Form 10-K: ALASKA AIR GROUP", ["company:bombardier_inc", "sec:other2"]),
        _event("2012-01-01T00:00:00Z", "Bombardier registry update", ["company:bombardier_inc"]),
        _event("2016-06-01T00:00:00Z", "Bombardier registry update", ["company:bombardier_inc"]),
    ]
    block = _assemble(nodes, seed="Bombardier Inc", timeline=timeline)
    assert len(block.evidence_gaps) == 1
    gap = block.evidence_gaps[0]
    assert gap.startswith("Bombardier Inc: ") and "company:bombardier_inc" not in gap
    assert "2012-01-01" in gap and "2016-06-01" in gap


def test_find_gaps_drops_events_about_listed_peers_and_uses_node_labels():
    timeline = [
        _event("2008-01-01T00:00:00Z", "a", ["n1", "other"]),
        _event("2020-01-01T00:00:00Z", "b", ["n1", "other"]),
        _event("2010-01-01T00:00:00Z", "c", ["n2"]),
        _event("2015-01-01T00:00:00Z", "d", ["n2"]),
    ]
    gaps = find_gaps(timeline, skip_node_ids={"other"}, drop_events_about={"other"}, node_labels={"n2": "Node Two"})
    assert gaps == ["Node Two: no dated evidence between 2010-01-01 and 2015-01-01 (1826 days)."]
    # nothing but events about other entities: nothing to report, and no false "no dated evidence at all"
    assert find_gaps(timeline[:2], skip_node_ids={"other"}, drop_events_about={"other"}) == []


def _registered_agent_nodes() -> list:
    return [
        _anchor("Boeing Company", "company:boeing_company"),
        _nd("lei:RVHJ", "THE BOEING COMPANY (US-DE)", tool="gleif_level1_level2_api",
            attrs={"legal_name": "THE BOEING COMPANY", "registered_address": "C/O CORPORATION SERVICE COMPANY, "
                   "251 LITTLE FALLS DRIVE, WILMINGTON, US"}),
        _nd("lei:OTHER", "Unrelated Shell Co (US-DE)", tool="gleif_level1_level2_api",
            attrs={"registered_address": "251 LITTLE FALLS DRIVE, WILMINGTON, US"}),
    ]


def test_the_subjects_own_registered_agent_address_is_info_not_high():
    block = _assemble(_registered_agent_nodes(), seed="Boeing Company")
    flags = {f["node_id"]: f for f in block.false_link_flags}
    assert flags["lei:RVHJ"]["severity"] == "info"
    assert flags["lei:RVHJ"]["reason"] == "registered-agent address shared by many entities; not evidence of a link"
    assert flags["lei:OTHER"]["severity"] == "high"  # a non-subject entity: unchanged


def test_a_shared_agent_address_stays_high_when_it_would_link_two_entities():
    nodes = _registered_agent_nodes() + [_nd("loc:csc", "251 Little Falls Drive, Wilmington, US", etype="Location")]
    edges = [_ed("lei:RVHJ", "REGISTERED_AT", "loc:csc"), _ed("lei:OTHER", "REGISTERED_AT", "loc:csc")]
    block = _assemble(nodes, edges, seed="Boeing Company")
    loc = [f for f in block.false_link_flags if f["node_id"] == "loc:csc"]
    assert loc and all(f["severity"] == "high" for f in loc)


def test_a_subject_only_agent_address_node_is_info():
    nodes = _registered_agent_nodes()[:2] + [
        _nd("loc:csc", "251 Little Falls Drive, Wilmington, US", etype="Location", flags=["MASS_REGISTERED_AGENT_ADDRESS"])
    ]
    block = _assemble(nodes, [_ed("lei:RVHJ", "REGISTERED_AT", "loc:csc")], seed="Boeing Company")
    loc = [f for f in block.false_link_flags if f["node_id"] == "loc:csc"]
    assert loc and all(f["severity"] == "info" for f in loc)


# ---------------------------------------------------------------- R7: counts are derived, not hard-coded


def test_the_implemented_source_count_is_derived_from_the_catalog():
    implemented = [s for s in SOURCES if s.implemented]
    assert implemented and len(implemented) == sum(1 for s in SOURCES if s.implemented)
    assert len({s.name for s in implemented}) == len(implemented)  # no duplicate rows inflating the count


def test_with_the_new_findings_the_block_still_validates_and_round_trips():
    block = _assemble(_rosneft_sanctions_graph(), log=_log(("ofac_sdn", "hit", "")))
    assert PIBlock.model_validate(block.model_dump(mode="json")) == block


@pytest.mark.parametrize("label", ["Rosneft", "ROSNEFT TRADING S.A."])
def test_assembly_does_not_mutate_the_input_graph(label: str):
    nodes = _rosneft_sanctions_graph()
    import copy

    before = copy.deepcopy(nodes)
    _assemble(nodes, log=_log(("ofac_sdn", "hit", "")), subject=label)
    assert nodes == before
