"""Final-verifier pass on PI block assembly (findings P1, P2, P5, P6).

Offline. Graph dicts are hand-built (``graph.to_dict()`` shape), as in test_pi_runtime_relevance_handoff.py and
test_pi_runtime_sanctions_ownership.py.

* P1: the EU consolidated list is never automated, so it is always named in ``sanctions.not_screened``.
* P2: the entity profile reads the real GLEIF attribute keys and surfaces reporting exceptions as ``parents`` lines.
* P5: the falsifier lead count uses only subject/related findings (the Bottom line population).
* P6: a source whose records are all about someone else is logged ``negative``, not ``hit``.
"""

# Replaces: test_pi_runtime_v4.py (consolidated 2026-11-09).

from __future__ import annotations

from typing import Any, Dict, Optional

from pi_helpers import NOW, all_five_sanctions_ran
from pi_helpers import source_log as _log

from bunnyhole.engine.pi import CaseType, PIBlock, PIEngagement
from bunnyhole.engine.pi_runtime import assemble_pi_block

EU_ENTRY = "EU Consolidated List: not automated (verify at https://www.sanctionsmap.eu/)"
NO_SUBJECT_RECORDS = "records found but none about the subject"


def _rc(tool: str, snippet: str = "") -> Dict[str, Any]:
    return {
        "receipt_id": f"rcpt_{tool}_{abs(hash((tool, snippet))) % 100_000}",
        "tool": tool,
        "source_url": f"https://example.test/{tool}/{abs(hash(snippet)) % 1000}",
        "sha256_proof": "ab" * 32,
        "timestamp": NOW,
        "extracted_fact": "f",
        "raw_snippet": snippet,
    }


def _nd(node_id: str, label: str, tool: str = "", attrs: Optional[dict] = None, etype: str = "Organization",
        snippet: str = "") -> Dict[str, Any]:
    return {
        "id": node_id, "label": label, "entity_type": etype,
        "receipts": [_rc(tool, snippet)] if tool else [], "attributes": attrs or {}, "risk_flags": [],
    }


def _eng(case_type: CaseType = CaseType.DUE_DILIGENCE) -> PIEngagement:
    return PIEngagement(engagement_id="pi_0123456789", case_type=case_type,
                        purpose="Vet a counterparty before signing a supply contract",
                        subject_is_person=False, created_at_utc=NOW)


def _assemble(nodes: list, *, seed: str = "Bombardier Inc", log: Optional[list] = None, **kw: Any) -> PIBlock:
    graph = {"seed_query": seed, "nodes": nodes, "edges": [], "timeline": []}
    return assemble_pi_block(kw.pop("engagement", None) or _eng(), graph, log or [], now_iso=NOW, **kw)


ALL_FIVE_RAN = all_five_sanctions_ran()


def _gleif(attrs: Optional[dict] = None, snippet: str = "", label: str = "BOMBARDIER INC. (CA-QC)") -> Dict[str, Any]:
    base = {"lei": "W7L3VLU8EHQY34Z36697", "legal_name": "BOMBARDIER INC.", "jurisdiction": "CA-QC"}
    base.update(attrs or {})
    return _nd("lei:W7L3VLU8EHQY34Z36697", label, tool="gleif_level1_level2_api", attrs=base, snippet=snippet)


# ---------------------------------------------------------------- P1: the EU list is always named


def test_lists_run_still_names_the_eu_list_as_not_screened_and_keeps_its_status():
    sanctions = _assemble([], log=ALL_FIVE_RAN).sanctions
    assert sanctions.status == "lists_run"
    assert sanctions.not_screened == [EU_ENTRY]
    assert len(sanctions.screened) == 5


def test_partial_and_not_run_screening_also_name_the_eu_list_last():
    partial = _assemble([], log=_log(("ca_sanctions", "negative", "ok"))).sanctions
    assert partial.status == "partial" and partial.not_screened[-1] == EU_ENTRY
    assert len(partial.not_screened) == 5  # four unreached lists plus the EU list
    not_run = _assemble([], log=[]).sanctions
    assert not_run.status == "not_run" and not_run.not_screened[-1] == EU_ENTRY
    assert len(not_run.not_screened) == 6


def test_the_sanctions_trigger_text_names_the_eu_list_when_all_five_ran():
    block = _assemble([], log=ALL_FIVE_RAN)
    trigger = next(t for t in block.escalation_triggers if "sanctions hit" in t.trigger)
    assert not trigger.fired
    assert "EU Consolidated List" in trigger.why and "https://www.sanctionsmap.eu/" in trigger.why
    assert "no sanctions/PEP listing" in trigger.why


def test_the_sanctions_trigger_text_names_the_eu_list_when_screening_was_partial():
    block = _assemble([], log=_log(("ca_sanctions", "negative", "ok")))
    trigger = next(t for t in block.escalation_triggers if "sanctions hit" in t.trigger)
    assert "EU Consolidated List" in trigger.why


# ---------------------------------------------------------------- P2: entity profile from the real attributes


def test_profile_reads_status_and_registered_address_from_the_gleif_attribute_keys():
    attrs = {"status": "ACTIVE", "registered_address": "400, chemin de la Cote-Vertu Ouest, Dorval, CA",
             "hq_city": "Dorval", "hq_country": "CA"}
    profile = _assemble([_gleif(attrs)]).entity_profile
    assert profile is not None
    assert profile.status == "ACTIVE"
    assert profile.registered_address == "400, chemin de la Cote-Vertu Ouest, Dorval, CA"
    assert profile.jurisdiction == "CA-QC"


def test_profile_reads_alternative_status_and_address_keys():
    profile = _assemble([_gleif({"entity_status": "INACTIVE", "legal_address": "1 Main St, Montreal, CA"})]).entity_profile
    assert profile is not None and profile.status == "INACTIVE"
    assert profile.registered_address == "1 Main St, Montreal, CA"


def test_profile_falls_back_to_the_headquarters_city_and_labels_it_as_such():
    profile = _assemble([_gleif({"hq_city": "Berlin", "hq_country": "DE"})]).entity_profile
    assert profile is not None
    assert profile.registered_address == "Headquarters: Berlin, DE"


def test_profile_never_invents_a_status_or_address_the_node_does_not_carry():
    profile = _assemble([_gleif()]).entity_profile
    assert profile is not None
    assert profile.status == "" and profile.registered_address == "" and profile.parents == []


def test_a_reporting_exception_attribute_becomes_a_parents_line_with_the_gleif_meaning():
    profile = _assemble([_gleif({"ultimate_parent_exception": "NO_KNOWN_PERSON"})]).entity_profile
    assert profile is not None
    assert profile.parents == ["Reporting exception: NO_KNOWN_PERSON (GLEIF: no known ultimate parent)"]


def test_every_documented_exception_category_has_a_gloss_and_unknown_ones_are_printed_plain():
    glosses = {
        "NON_CONSOLIDATING": "GLEIF: the entity is not consolidated by a parent",
        "NATURAL_PERSONS": "GLEIF: the parent is a natural person or persons",
        "NO_LEI": "GLEIF: the parent has no LEI",
    }
    for category, gloss in glosses.items():
        profile = _assemble([_gleif({"direct_parent_exception": category})]).entity_profile
        assert profile is not None
        assert profile.parents == [f"Reporting exception: {category} ({gloss})"]
    odd = _assemble([_gleif({"reporting_exception": "SOMETHING_NEW"})]).entity_profile
    assert odd is not None and odd.parents == ["Reporting exception: SOMETHING_NEW (GLEIF)"]


def test_exceptions_given_as_dicts_or_lists_are_read_and_deduplicated():
    attrs = {"reporting_exceptions": [{"category": "NO_KNOWN_PERSON", "reason": "x"}, "NO_KNOWN_PERSON", "NO_LEI"]}
    profile = _assemble([_gleif(attrs)]).entity_profile
    assert profile is not None
    assert [p.split(" (")[0] for p in profile.parents] == [
        "Reporting exception: NO_KNOWN_PERSON", "Reporting exception: NO_LEI",
    ]


def test_an_exception_named_in_the_receipt_snippet_is_read():
    profile = _assemble([_gleif(snippet="LEI=W7L3 | legalName=BOMBARDIER INC. | exception=NON_CONSOLIDATING")]).entity_profile
    assert profile is not None
    assert profile.parents == ["Reporting exception: NON_CONSOLIDATING (GLEIF: the entity is not consolidated by a parent)"]


def test_an_exception_does_not_hide_a_real_parent_and_comes_after_it():
    parent = _nd("lei:PARENT0000000000001", "Parent Holdings Ltd (GB)", tool="gleif_level2_ultimate_parent",
                 attrs={"lei": "PARENT0000000000001", "jurisdiction": "GB"})
    graph = {
        "seed_query": "Bombardier Inc",
        "nodes": [_gleif({"direct_parent_exception": "NO_LEI"}), parent],
        "edges": [{"id": "e1", "source_id": parent["id"], "target_id": "lei:W7L3VLU8EHQY34Z36697",
                   "relation": "ULTIMATE_PARENT_OF", "receipts": [], "event_date": None}],
        "timeline": [],
    }
    profile = assemble_pi_block(_eng(), graph, [], now_iso=NOW).entity_profile
    assert profile is not None
    assert profile.parents[0] == "Parent Holdings Ltd"
    assert profile.parents[1].startswith("Reporting exception: NO_LEI")


# ---------------------------------------------------------------- P5: falsifier lead count


def _doc(node_id: str, label: str, tool: str) -> Dict[str, Any]:
    return _nd(node_id, label, tool=tool)


def test_falsifier_lead_count_uses_only_subject_and_related_findings():
    nodes = [
        _gleif(),
        _nd("article:1", "Bombardier Inc wins a contract", tool="google_news_rss + shingling_detector"),
        _doc("loc:a", "Address A", "gleif_level1_level2_api"),
        _doc("loc:b", "Address B", "gleif_level1_level2_api"),
        _doc("loc:c", "Address C", "gleif_level1_level2_api"),
    ]
    nodes[2]["entity_type"] = nodes[3]["entity_type"] = nodes[4]["entity_type"] = "Location"
    block = _assemble(nodes)
    relevant = [f for f in block.findings if f.relevance in ("subject", "related")]
    unknown = [f for f in block.findings if f.relevance == "unknown"]
    assert len(relevant) >= 2 and len(unknown) == 3
    lead_lines = [t for t in block.falsifiers if "single-source" in t]
    assert lead_lines
    text = " ".join(lead_lines)
    for finding in unknown:
        assert finding.node_id not in text


def test_falsifier_lead_statement_count_matches_the_relevant_population():
    nodes = [_nd(f"article:{i}", f"Bombardier Inc story {i}", tool="google_news_rss + shingling_detector")
             for i in range(4)]
    nodes += [_doc(f"hn:{i}", f"HN: unrelated gardening {i}", "hackernews_algolia_archive") for i in range(5)]
    block = _assemble(nodes)
    relevant = [f for f in block.findings if f.relevance in ("subject", "related")]
    statement = next(t for t in block.falsifiers if "single-source leads" in t)
    assert f"any of the {len(relevant)} single-source" in statement


# ---------------------------------------------------------------- P6: a hit needs a finding about the subject


def test_a_source_whose_records_are_all_unrelated_is_logged_negative_with_a_detail():
    nodes = [
        _gleif({"status": "ACTIVE"}),
        _nd("sec:1", "SEC Form 10-K: Pinnacle Airlines Corp", tool="sec_edgar_efts + edgartools"),
        _nd("sec:2", "SEC Form 10-Q: Pinnacle Airlines Corp", tool="sec_edgar_efts + edgartools"),
    ]
    log = _log(("gleif", "hit", "1 new node(s)"), ("sec_edgar", "hit", "2 new node(s), 2 new receipt(s)"))
    block = _assemble(nodes, log=log)
    sec = next(e for e in block.source_log if e.source == "sec_edgar")
    gleif = next(e for e in block.source_log if e.source == "gleif")
    assert sec.status == "negative" and NO_SUBJECT_RECORDS in sec.detail
    assert gleif.status == "hit"
    registry = next(row for row in block.coverage if row.source_class == "corporate_registry")
    assert registry.outcome == "hit"  # GLEIF still delivered a record about the subject
    assert registry.sources == ["gleif", "sec_edgar"]  # both ran; only the outcome reflects relevance


def test_a_class_with_only_unrelated_hits_reads_negative():
    nodes = [_nd("sec:1", "SEC Form 10-K: Pinnacle Airlines Corp", tool="sec_edgar_efts + edgartools")]
    block = _assemble(nodes, log=_log(("sec_edgar", "hit", "1 new node(s)")))
    registry = next(row for row in block.coverage if row.source_class == "corporate_registry")
    assert registry.searched and registry.outcome == "negative"


def test_a_source_with_one_related_record_stays_a_hit():
    nodes = [
        _nd("sec:1", "SEC Form 10-K: Pinnacle Airlines Corp", tool="sec_edgar_efts + edgartools"),
        _nd("sec:2", "SEC Form 10-K: Bombardier Inc", tool="sec_edgar_efts + edgartools"),
    ]
    block = _assemble(nodes, log=_log(("sec_edgar", "hit", "2 new node(s)")))
    sec = next(e for e in block.source_log if e.source == "sec_edgar")
    assert sec.status == "hit" and sec.detail == "2 new node(s)"


def test_a_hit_from_a_source_without_a_known_receipt_tool_is_left_alone():
    block = _assemble([_nd("x:1", "Anything", tool="mystery_tool")], log=_log(("mystery_source", "hit", "1 new node(s)")))
    assert [e.status for e in block.source_log] == ["hit"]


def test_negative_skipped_and_error_entries_are_never_rewritten():
    log = _log(("sec_edgar", "negative", "ran"), ("gleif", "skipped", "no key"), ("nonprofit_990s", "error", "HTTP 404"))
    block = _assemble([], log=log)
    assert [(e.source, e.status, e.detail) for e in block.source_log] == [
        ("sec_edgar", "negative", "ran"), ("gleif", "skipped", "no key"), ("nonprofit_990s", "error", "HTTP 404"),
    ]
