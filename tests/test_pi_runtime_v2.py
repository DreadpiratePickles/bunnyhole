"""Analysis-layer quality upgrade of the PI stream: relevance, entity profile, sanctions honesty, handoff, falsifiers.

Offline. Graph dicts are hand-built (``graph.to_dict()`` shape). The examples are the false positives two live
reports (Bombardier Inc, Rosneft) showed: other companies' filings, forum posts, tokens, a lookalike nonprofit,
a sanctions list matched but reported as "no sanctions listing", and a licensed-database action for a company
address.
"""

from __future__ import annotations

import copy
from typing import Any, Dict, List, Optional

import pytest

from bunnyhole.engine import pi_runtime
from bunnyhole.engine.pi import (
    CaseType,
    EntityProfile,
    Finding,
    FindingLabel,
    OwnershipBlock,
    PIBlock,
    PIEngagement,
    SanctionsScreening,
    SourceLogEntry,
)
from bunnyhole.engine.pi_analysis import falsifiers_for, find_gaps
from bunnyhole.engine.pi_escalation import handoff_sheet
from bunnyhole.engine.pi_runtime import SOURCE_CLASS_MAP, assemble_pi_block

NOW = "2026-11-09T00:00:00+00:00"
SEMA_URL = "https://www.international.gc.ca/sema-list"


# ---------------------------------------------------------------- builders


def _rc(tool: str, url: str = "", rid: str = "") -> Dict[str, Any]:
    return {
        "receipt_id": rid or f"rcpt_{tool}_{abs(hash((tool, url))) % 100_000}",
        "tool": tool,
        "source_url": url or f"https://example.test/{tool}",
        "sha256_proof": "ab" * 32,
        "timestamp": NOW,
        "extracted_fact": "f",
    }


def _nd(node_id: str, label: str = "", etype: str = "Organization", tool: str = "", attrs: Optional[dict] = None,
        flags: Optional[list] = None, url: str = "") -> Dict[str, Any]:
    return {
        "id": node_id,
        "label": label or node_id,
        "entity_type": etype,
        "receipts": [_rc(tool, url)] if tool else [],
        "attributes": attrs or {},
        "risk_flags": flags or [],
    }


def _ed(src: str, rel: str, dst: str) -> Dict[str, Any]:
    return {"id": f"e_{src}_{rel}_{dst}", "source_id": src, "target_id": dst, "relation": rel, "receipts": [],
            "event_date": None}


def _eng(case_type: CaseType = CaseType.DUE_DILIGENCE, person: bool = False, **kw: Any) -> PIEngagement:
    # built directly: the purpose gates (PIEngagement.build) are covered by their own tests
    return PIEngagement(engagement_id="pi_0123456789", case_type=case_type,
                        purpose="Vet a counterparty before signing a supply contract",
                        subject_is_person=person, created_at_utc=NOW, **kw)


def _log(*rows: tuple) -> List[SourceLogEntry]:
    return [SourceLogEntry(source=s, target="x", status=st, detail=d, at_utc=NOW) for s, st, d in rows]


def _assemble(nodes: list, edges: Optional[list] = None, *, seed: str = "", log: Optional[list] = None,
              timeline: Optional[list] = None, engagement: Optional[PIEngagement] = None, **kw: Any) -> PIBlock:
    graph = {"seed_query": seed, "nodes": nodes, "edges": edges or [], "timeline": timeline or []}
    return assemble_pi_block(engagement or _eng(), graph, log or [], now_iso=NOW, **kw)


def _by_id(block: PIBlock) -> Dict[str, Finding]:
    return {f.node_id: f for f in block.findings}


ALL_FIVE_RAN = _log(("ca_sanctions", "negative", "ok"), ("opensanctions", "negative", "ok"),
                    ("ofac_sdn", "negative", "ok"), ("un_consolidated", "negative", "ok"),
                    ("uk_sanctions_list", "negative", "ok"))


# ---------------------------------------------------------------- (1) relevance wired into findings


def _rosneft_graph() -> list:
    return [
        _nd("seed:rosneft", "Rosneft", tool="bunnyhole_seed"),
        _nd("sanction:ca:1", "⛔ Rosneft PJSC", tool="gac_sema_sanctions", url=SEMA_URL),
        _nd("np:1", "Rosfest Inc", tool="propublica_irs_990_api"),
        _nd("hn:1", "Why Agile Often Fails", tool="hackernews_algolia_archive"),
        _nd("dex:1", "$ROBINCAT", tool="dexscreener_lp_forensics"),
        _nd("cik:1", "Pinnacle Airlines Corp", tool="sec_edgar_efts + edgartools"),
    ]


def test_each_finding_carries_relevance_and_a_reason_seeded_from_the_graph_seed_query():
    found = _by_id(_assemble(_rosneft_graph(), seed="Rosneft"))
    assert found["sanction:ca:1"].relevance == "subject"
    for noise in ("np:1", "hn:1", "dex:1", "cik:1"):
        assert found[noise].relevance == "unrelated", noise
        assert found[noise].relevance_reason
    assert found["sanction:ca:1"].relevance_reason


def test_subject_is_seeded_from_the_selectors_when_the_graph_has_no_seed_query():
    block = _assemble(_rosneft_graph(), seed="", selectors={"organizations": ["Rosneft"]})
    assert _by_id(block)["sanction:ca:1"].relevance == "subject"


def test_explicit_subject_argument_wins():
    block = _assemble(_rosneft_graph(), seed="something else", subject="Rosneft")
    assert _by_id(block)["sanction:ca:1"].relevance == "subject"


def test_without_any_subject_name_relevance_is_unknown_not_guessed():
    found = _by_id(_assemble(_rosneft_graph(), seed=""))
    assert {f.relevance for f in found.values()} == {"unknown"}


def test_a_node_linked_to_the_subject_by_an_ownership_or_officer_edge_is_related():
    nodes = [
        _nd("seed:b", "Bombardier Inc", tool="bunnyhole_seed"),
        _nd("lei:1", "Bombardier Inc", tool="gleif_level1_level2_api"),
        _nd("p:1", "Alain Bellemare", etype="Person", tool="companies_house"),
        _nd("p:2", "Some Unlinked Person", etype="Person", tool="companies_house"),
    ]
    found = _by_id(_assemble(nodes, [_ed("p:1", "OFFICER_OF", "lei:1")], seed="Bombardier Inc"))
    assert found["lei:1"].relevance == "subject"
    assert found["p:1"].relevance == "related"
    assert found["p:2"].relevance == "unrelated"


def test_a_filing_or_litigation_edge_does_not_make_a_node_related():
    nodes = [_nd("lei:1", "Bombardier Inc", tool="gleif_level1_level2_api"),
             _nd("cik:9", "Pinnacle Airlines Corp", tool="sec_edgar_efts + edgartools")]
    found = _by_id(_assemble(nodes, [_ed("lei:1", "FILED", "cik:9")], seed="Bombardier Inc"))
    assert found["cik:9"].relevance == "unrelated"


def test_bombardier_division_is_related_and_the_namesake_is_flagged_as_a_collision_not_dropped():
    nodes = [
        _nd("lei:1", "Bombardier Inc", tool="gleif_level1_level2_api"),
        _nd("lei:2", "Bombardier Transport Canada", tool="gleif_level1_level2_api"),
        _nd("lei:3", "Bombardier Produits Récréatifs", tool="gleif_level1_level2_api"),
    ]
    block = _assemble(nodes, seed="Bombardier Inc")
    found = _by_id(block)
    assert found["lei:2"].relevance == "related"
    assert found["lei:3"].relevance == "unrelated"
    assert set(found) == {"lei:1", "lei:2", "lei:3"}  # the JSON keeps everything
    assert any("possible name collision" in n and "Récréatifs" in n for n in block.identity_notes)


def test_relevance_does_not_touch_the_graph_or_the_other_finding_fields():
    nodes = _rosneft_graph()
    before = copy.deepcopy(nodes)
    block = _assemble(nodes, seed="Rosneft")
    assert nodes == before
    assert len(block.findings) == 5
    assert all(f.finding_label is FindingLabel.LEAD and f.source_count == 1 for f in block.findings)
    assert PIBlock.model_validate(block.model_dump(mode="json")) == block


# ---------------------------------------------------------------- (2) entity profile


def _gleif(node_id: str = "lei:549300", label: str = "🏛️ Bombardier Inc (CA)", **attrs: Any) -> dict:
    base = {"lei": "549300ABC", "legal_name": "Bombardier Inc.", "jurisdiction": "CA", "status": "ACTIVE",
            "registered_address": "400 Chemin de la Cote-Vertu Ouest, Dorval, CA"}
    base.update(attrs)
    return _nd(node_id, label, tool="gleif_level1_level2_api", attrs=base,
               url="https://search.gleif.org/#/record/549300ABC")


def test_entity_profile_is_built_from_the_subject_registry_node_and_its_parents():
    nodes = [_gleif(), _nd("lei:PARENT", "👑 Bombardier Holdings (CA)", tool="gleif_level2_ultimate_parent")]
    block = _assemble(nodes, [_ed("lei:PARENT", "ULTIMATE_PARENT_OF", "lei:549300")], seed="Bombardier Inc")
    profile = block.entity_profile
    assert isinstance(profile, EntityProfile)
    assert profile.legal_name == "Bombardier Inc."
    assert profile.lei == "549300ABC"
    assert profile.status == "ACTIVE"
    assert profile.jurisdiction == "CA"
    assert "Cote-Vertu" in profile.registered_address
    assert profile.parents == ["Bombardier Holdings"]
    assert any("gleif" in s.lower() for s in profile.sources)


def test_entity_profile_fills_only_what_the_nodes_carry():
    node = _nd("lei:1", "Bombardier Inc", tool="gleif_level1_level2_api", attrs={"lei": "L1"})
    profile = _assemble([node], seed="Bombardier Inc").entity_profile
    assert profile is not None
    assert profile.lei == "L1" and profile.legal_name == "Bombardier Inc"
    assert profile.status == "" and profile.jurisdiction == "" and profile.registered_address == "" and profile.parents == []


def test_entity_profile_uses_companies_house_and_fills_gaps_from_it():
    ch = _nd("company:uk:123", "Acme Widgets Ltd", tool="companies_house",
             attrs={"company_number": "123", "company_status": "active", "address": "1 High St, London"},
             url="https://find-and-update.company-information.service.gov.uk/company/123")
    profile = _assemble([ch], seed="Acme Widgets").entity_profile
    assert profile is not None
    assert profile.status == "active" and profile.registered_address == "1 High St, London"
    assert any("Companies House" in s for s in profile.sources)


def test_entity_profile_is_none_when_nothing_matched_the_subject():
    wrong = _gleif(label="Rosfest Inc", legal_name="Rosfest Inc")
    assert _assemble([wrong], seed="Bombardier Inc").entity_profile is None
    assert _assemble([], seed="Bombardier Inc").entity_profile is None
    assert _assemble([_gleif()], seed="").entity_profile is None  # no subject name: nothing can be matched


def test_entity_profile_ignores_non_registry_sources():
    news = _nd("n:1", "Bombardier Inc", tool="google_news_rss + shingling_detector",
               attrs={"jurisdiction": "XX", "status": "BANKRUPT"})
    assert _assemble([news], seed="Bombardier Inc").entity_profile is None


# ---------------------------------------------------------------- (3) sanctions honesty


def test_sanctions_not_run_when_no_list_was_screened():
    sanctions = _assemble([], log=[]).sanctions
    assert sanctions.status == "not_run"
    assert sanctions.screened == [] and sanctions.hits == []
    assert len(sanctions.not_screened) == 5 + 1  # five automated lists plus the EU list (never automated)


def test_sanctions_partial_names_what_ran_and_what_did_not_with_reasons():
    log = _log(("ca_sanctions", "hit", "1 match"), ("opensanctions", "skipped", "needs API key"),
               ("ofac_sdn", "error", "HTTP 401"), ("un_consolidated", "negative", "ok"))
    sanctions = _assemble([], log=log).sanctions
    assert sanctions.status == "partial"
    assert sanctions.screened == ["Canada SEMA", "UN Consolidated List"]
    text = " | ".join(sanctions.not_screened)
    assert "OpenSanctions" in text and "needs API key" in text
    assert "OFAC SDN" in text and "HTTP 401" in text
    assert "UK Sanctions List" in text  # never dispatched
    assert len(sanctions.not_screened) == 3 + 1  # three unreached lists plus the EU list (never automated)


def test_sanctions_lists_run_only_when_all_five_ran():
    assert _assemble([], log=ALL_FIVE_RAN).sanctions.status == "lists_run"
    four = [e for e in ALL_FIVE_RAN if e.source != "uk_sanctions_list"]
    assert _assemble([], log=four).sanctions.status == "partial"


def test_a_skipped_entry_never_counts_as_screened_even_after_a_negative_elsewhere():
    log = _log(("opensanctions", "skipped", "needs API key"))
    assert _assemble([], log=log).sanctions.screened == []


def test_sanctions_hit_is_a_soft_match_with_list_name_url_and_node_id():
    nodes = [_nd("sanction:ca:1", "⛔ Rosneft PJSC", tool="gac_sema_sanctions", url=SEMA_URL),
             _nd("sanction:os:2", "🏅 Rosneft Oil Company", tool="opensanctions_yente",
                 url="https://www.opensanctions.org/entities/NK-1/")]
    sanctions = _assemble(nodes, log=_log(("ca_sanctions", "hit", "1")), seed="Rosneft").sanctions
    by_list = {h["list"]: h for h in sanctions.hits}
    assert set(by_list) == {"Canada SEMA", "OpenSanctions"}
    hit = by_list["Canada SEMA"]
    assert hit["name"] == "Rosneft PJSC" and hit["url"] == SEMA_URL and hit["node_id"] == "sanction:ca:1"
    assert hit["match"].startswith("soft: verify on the primary list")


def test_a_listing_whose_name_does_not_resemble_the_subject_is_not_a_hit_but_is_noted():
    nodes = [_nd("sanction:os:9", "⛔ Acne Trading Corp", tool="opensanctions_yente")]
    block = _assemble(nodes, log=_log(("opensanctions", "hit", "1")), seed="Rosneft")
    assert block.sanctions.hits == []
    assert any("Acne Trading" in n and "not treated as a hit" in n for n in block.notices)
    trig = next(t for t in block.escalation_triggers if "sanctions hit" in t.trigger)
    assert not trig.fired


def _trigger(block: PIBlock, fragment: str = "sanctions hit"):
    return next(t for t in block.escalation_triggers if fragment in t.trigger)


def test_partial_screening_never_says_no_sanctions_listing():
    log = _log(("ca_sanctions", "negative", "ok"), ("opensanctions", "skipped", "needs API key"))
    trig = _trigger(_assemble([], log=log))
    assert not trig.fired
    assert "not fired on the lists screened (Canada SEMA)" in trig.why
    assert "NOT screened" in trig.why and "OpenSanctions" in trig.why
    assert "no sanctions/PEP listing" not in trig.why


def test_not_run_screening_is_not_evaluated_not_clean():
    trig = _trigger(_assemble([], log=[]))
    assert not trig.fired
    assert "no sanctions list was screened" in trig.why and "NOT screened" in trig.why


def test_a_sanctions_hit_fires_the_trigger_even_when_screening_was_partial():
    nodes = [_nd("sanction:ca:1", "⛔ Rosneft PJSC", tool="gac_sema_sanctions")]
    block = _assemble(nodes, log=_log(("ca_sanctions", "hit", "1"), ("opensanctions", "skipped", "no key")),
                      seed="Rosneft")
    trig = _trigger(block)
    assert trig.fired and "sanction:ca:1" in trig.why and "soft name match" in trig.why
    assert "NOT screened" in trig.why  # the partial coverage is still stated next to the hit


def test_all_five_lists_clean_may_say_no_listing_and_names_the_eu_gap():
    trig = _trigger(_assemble([], log=ALL_FIVE_RAN))
    assert not trig.fired
    assert "no sanctions/PEP listing" in trig.why and "EU" in trig.why


def test_sanctions_block_validates_as_json():
    block = _assemble([_nd("s:1", "Rosneft PJSC", tool="gac_sema_sanctions")], log=_log(("ca_sanctions", "hit", "1")),
                      seed="Rosneft")
    assert isinstance(block.sanctions, SanctionsScreening)
    assert PIBlock.model_validate(block.model_dump(mode="json")) == block


# ---------------------------------------------------------------- (4) source maps


def test_new_sanctions_sources_map_to_the_sanctions_class_and_the_playbook_steps():
    for name in ("ofac_sdn", "un_consolidated", "uk_sanctions_list"):
        assert SOURCE_CLASS_MAP[name] == "sanctions_pep"
    pmap = pi_runtime.PLAYBOOK_SOURCE_MAP
    assert pmap["OFAC Sanctions List Search"] == ("ofac_sdn",)
    assert pmap["UN Security Council Consolidated List"] == ("un_consolidated",)
    assert pmap["UK OFSI Consolidated List"] == ("uk_sanctions_list",)
    assert "EU Sanctions Map" not in pmap  # no EU source: stays not run, never guessed


def test_the_sanctions_step_is_done_only_when_every_listed_source_ran():
    from bunnyhole.engine.pi_reference import playbook_for

    step = next(p for p in pi_runtime.playbook_progress_for(playbook_for(CaseType.DUE_DILIGENCE), ALL_FIVE_RAN)
                if "Screen sanctions" in p.action)
    assert step.status == "partial"  # the EU Sanctions Map has no automated source
    assert "not automated: EU Sanctions Map" in step.evidence


# ---------------------------------------------------------------- (5) handoff / next step


def _sheet(person: bool, case_type: CaseType = CaseType.DUE_DILIGENCE, **kw: Any) -> List[str]:
    engagement = _eng(case_type, person=person, **({"matter_ref": "24-CV-1"} if case_type is CaseType.LOCATE else {}))
    ids = {"addresses": ["400, chemin de la Cote-Vertu Ouest"], "names": ["Bombardier Inc"], "phones": ["+15145550100"]}
    return handoff_sheet(engagement, ids, [], **kw)


def test_entity_due_diligence_never_gets_licensed_database_or_field_verification_lines():
    text = "\n".join(_sheet(person=False))
    assert "Run through licensed database" not in text
    assert "Field verification" not in text
    assert "Cote-Vertu" in text  # still listed, as an unverified lead for a primary source
    assert "unverified lead" in text


@pytest.mark.parametrize("case_type", [CaseType.LOCATE, CaseType.MISSING_PERSON])
def test_locate_and_missing_person_keep_licensed_database_and_field_lines(case_type: CaseType):
    lines = handoff_sheet(
        _eng(case_type, person=False, **({"matter_ref": "24-CV-1"} if case_type is CaseType.LOCATE else {})),
        {"addresses": ["12 Example Rd"]}, [],
    )
    text = "\n".join(lines)
    assert "Run through licensed database: 12 Example Rd" in text and "Field verification" in text


def test_person_subject_keeps_the_old_lines():
    text = "\n".join(_sheet(person=True, case_type=CaseType.BACKGROUND))
    assert "Run through licensed database: 400, chemin de la Cote-Vertu Ouest" in text
    assert "Field verification" in text


def test_entity_partial_sanctions_adds_verify_lines_with_primary_list_urls():
    sanctions = SanctionsScreening(
        status="partial", screened=["Canada SEMA"],
        not_screened=["OpenSanctions (skipped: needs API key)", "OFAC SDN (not run)", "UN Consolidated List (not run)",
                      "UK Sanctions List (not run)"],
    )
    text = "\n".join(_sheet(person=False, sanctions=sanctions))
    for url in ("https://sanctionssearch.ofac.treas.gov/",
                "https://main.un.org/securitycouncil/en/content/un-sc-consolidated-list",
                "https://www.gov.uk/government/publications/the-uk-sanctions-list",
                "https://www.sanctionsmap.eu/"):
        assert url in text
    assert any(line.startswith("Verify ") for line in _sheet(person=False, sanctions=sanctions))


def test_entity_sanctions_hit_line_names_the_list_url_and_the_soft_match():
    sanctions = SanctionsScreening(
        status="lists_run", screened=["Canada SEMA"],
        hits=[{"list": "Canada SEMA", "name": "Rosneft PJSC", "match": "soft: verify on the primary list",
               "url": SEMA_URL, "node_id": "sanction:ca:1"}],
    )
    lines = _sheet(person=False, sanctions=sanctions)
    hit_line = next(line for line in lines if line.startswith("Verify the sanctions hit on the primary list"))
    assert SEMA_URL in hit_line or "international.gc.ca" in hit_line
    assert "Rosneft PJSC" in hit_line


def test_entity_with_all_lists_clean_and_no_hit_gets_no_sanctions_line():
    sanctions = SanctionsScreening(status="lists_run", screened=["a", "b", "c", "d", "e"])
    assert not any("sanction" in line.lower() and line.startswith("Verify") for line in _sheet(False, sanctions=sanctions))


def test_entity_registry_line_uses_the_entity_profile_jurisdiction():
    profile = EntityProfile(legal_name="Bombardier Inc.", lei="L1", jurisdiction="CA-QC")
    line = next(x for x in _sheet(person=False, entity_profile=profile)
                if x.startswith("Confirm corporate status and beneficial ownership on the primary registry:"))
    assert "Qu" in line  # Quebec enterprise register
    gb = EntityProfile(jurisdiction="GB")
    assert "Companies House" in "\n".join(_sheet(person=False, entity_profile=gb))


def test_entity_registry_line_falls_back_without_a_profile():
    lines = _sheet(person=False)
    assert any(x.startswith("Confirm corporate status and beneficial ownership on the primary registry:")
               for x in lines)


def test_person_sheet_gets_no_entity_action_lines():
    sanctions = SanctionsScreening(status="partial", not_screened=["OFAC SDN (not run)"])
    text = "\n".join(_sheet(person=True, case_type=CaseType.BACKGROUND, sanctions=sanctions))
    assert "Confirm corporate status" not in text
    assert "Verify the sanctions" not in text and "primary list" not in text


def test_old_call_signature_still_works():
    lines = handoff_sheet(_eng(person=True, case_type=CaseType.BACKGROUND), {"names": ["Jane Debtor"]}, [])
    assert any(line.startswith("Run through licensed database: Jane Debtor") for line in lines)


def test_assembled_entity_block_has_no_licensed_database_line_for_a_company_address():
    nodes = [_gleif(), _nd("sanction:ca:1", "⛔ Rosneft PJSC", tool="gac_sema_sanctions", url=SEMA_URL)]
    block = _assemble(nodes, log=_log(("ca_sanctions", "hit", "1")), seed="Bombardier Inc")
    text = "\n".join(block.handoff_sheet)
    assert "Run through licensed database" not in text
    assert "Confirm corporate status and beneficial ownership on the primary registry:" in text
    assert "Verify" in text


# ---------------------------------------------------------------- (6) falsifiers and gaps


def _lead(i: int, relevance: str = "subject") -> Finding:
    return Finding(node_id=f"n{i}", label=f"Lead {i}", finding_label=FindingLabel.LEAD, source_count=1,
                   relevance=relevance)  # type: ignore[arg-type]


def test_many_single_source_leads_collapse_into_one_line_naming_up_to_five_with_the_count():
    findings = [_lead(i) for i in range(20)]
    out = falsifiers_for(CaseType.DUE_DILIGENCE, findings, [], OwnershipBlock(), collapse_leads_above=1)
    base = falsifiers_for(CaseType.DUE_DILIGENCE, [], [], OwnershipBlock())
    assert len(out) == len(base) + 1
    line = out[-1]
    assert "20" in line and line.count("Lead ") == 5 and "+15 more" in line


def test_leads_are_named_most_relevant_first_and_unrelated_ones_are_skipped():
    findings = [_lead(1, "unrelated"), _lead(2, "related"), _lead(3, "subject"), _lead(4, "unrelated")]
    out = falsifiers_for(CaseType.DUE_DILIGENCE, findings, [], OwnershipBlock(), collapse_leads_above=1)
    line = out[-1]
    assert "Lead 3" in line and "Lead 2" in line
    assert "Lead 1" not in line and "Lead 4" not in line
    assert line.index("Lead 3") < line.index("Lead 2")


def test_a_single_lead_keeps_its_own_line_and_the_old_default_is_unchanged():
    out = falsifiers_for(CaseType.LOCATE, [_lead(1), _lead(2)], [], OwnershipBlock())
    base = falsifiers_for(CaseType.LOCATE, [], [], OwnershipBlock())
    assert len(out) == len(base) + 2  # default keeps up to two individual lead lines (back-compat)
    assert len(falsifiers_for(CaseType.LOCATE, [_lead(1)], [], OwnershipBlock(), collapse_leads_above=1)) == len(base) + 1


def test_one_line_per_unresolved_node_and_per_contradiction_is_kept():
    from bunnyhole.engine.pi import Contradiction

    own = OwnershipBlock(unresolved=["lei:a", "lei:b (max_levels reached)"])
    contradictions = [Contradiction(kind="k1", description="d1", node_ids=["x"]),
                      Contradiction(kind="k2", description="d2", node_ids=["y"])]
    out = falsifiers_for(CaseType.DUE_DILIGENCE, [_lead(i) for i in range(9)], contradictions, own,
                         collapse_leads_above=1)
    base = falsifiers_for(CaseType.DUE_DILIGENCE, [], [], OwnershipBlock())
    assert len(out) == len(base) + 2 + 1 + 2


def test_falsifiers_skip_unresolved_nodes_and_contradictions_driven_by_unrelated_nodes():
    from bunnyhole.engine.pi import Contradiction

    own = OwnershipBlock(unresolved=["lei:noise", "lei:real"])
    contradictions = [Contradiction(kind="k1", description="noise contradiction", node_ids=["lei:noise"]),
                      Contradiction(kind="k2", description="real contradiction", node_ids=["lei:real"])]
    out = "\n".join(falsifiers_for(CaseType.DUE_DILIGENCE, [], contradictions, own, unrelated_node_ids={"lei:noise"}))
    assert "lei:real" in out and "real contradiction" in out
    assert "lei:noise" not in out and "noise contradiction" not in out


def test_gaps_skip_unrelated_nodes():
    timeline = [
        {"timestamp": "2010-01-01T00:00:00Z", "title": "a", "node_ids": ["noise"]},
        {"timestamp": "2020-01-01T00:00:00Z", "title": "b", "node_ids": ["noise"]},
        {"timestamp": "2010-01-01T00:00:00Z", "title": "a", "node_ids": ["real"]},
        {"timestamp": "2020-01-01T00:00:00Z", "title": "b", "node_ids": ["real"]},
    ]
    gaps = find_gaps(timeline, skip_node_ids={"noise"})
    assert len(gaps) == 1 and "real" in gaps[0]
    assert find_gaps(timeline, skip_node_ids={"noise", "real"}) == []  # all skipped is not "no dated evidence"


def test_assembled_block_collapses_leads_and_skips_unrelated_noise_in_falsifiers_and_gaps():
    divisions = ["Transport", "Aerospace", "Aviation", "Services", "Technologies", "Systems", "Solutions", "Logistics"]
    nodes = [_nd(f"lead:{i}", f"Bombardier {word}", tool=f"tool_{i}") for i, word in enumerate(divisions)]
    nodes += [_nd(f"noise:{i}", f"Pinnacle Noise {i}", tool="sec_edgar") for i in range(8)]
    timeline = [{"timestamp": "2010-01-01T00:00:00Z", "title": "a", "node_ids": ["noise:0"]},
                {"timestamp": "2020-01-01T00:00:00Z", "title": "b", "node_ids": ["noise:0"]}]
    block = _assemble(nodes, seed="Bombardier Inc", timeline=timeline)
    lead_lines = [f for f in block.falsifiers if "single-source lead" in f]
    assert len(lead_lines) == 1 and "Pinnacle" not in lead_lines[0] and "8" in lead_lines[0]
    assert not any("noise:0" in g for g in block.evidence_gaps)
    assert len(block.findings) == 16  # the findings themselves are all kept


# ---------------------------------------------------------------- (7) spurious nominee/secrecy trigger


def _ownership_nodes(flags: Optional[list] = None, tool: str = "gleif_level1_level2_api", cik: bool = False) -> list:
    node_id = "cik:777" if cik else "lei:orphan"
    return [_nd(node_id, "Acme Corp", tool=tool, flags=flags or [], attrs={"ticker": "ACME"} if cik else {}),
            _nd("co:sub", "Acme Sub", tool="gleif_level1_level2_api")]


def _ownership_trigger(nodes: list) -> Any:
    edges = [_ed(nodes[0]["id"], "ULTIMATE_PARENT_OF", "co:sub")]
    return _trigger(_assemble(nodes, edges, seed="Acme"), "ownership chain ends")


def test_ownership_trigger_cites_the_secrecy_flag_when_one_is_present():
    trig = _ownership_trigger(_ownership_nodes(flags=["OFFSHORE_SECRECY_JURISDICTION_KY"]))
    assert trig.fired and "OFFSHORE_SECRECY_JURISDICTION_KY" in trig.why


def test_ownership_trigger_without_a_flag_says_it_is_an_unresolved_chain_not_a_nominee_finding():
    # Requirement change 2026-11-09 (third quality pass, R5): without nominee or secrecy evidence the trigger no
    # longer fires; it still names the unresolved node and says that no such evidence was found.
    trig = _ownership_trigger(_ownership_nodes())
    assert not trig.fired and "lei:orphan" in trig.why
    assert "no nominee or secrecy-jurisdiction evidence" in trig.why


def test_ownership_trigger_is_not_evaluated_for_a_publicly_listed_registrant():
    trig = _ownership_trigger(_ownership_nodes(tool="sec_edgar_efts + edgartools", cik=True))
    assert not trig.fired
    assert trig.why.startswith("not evaluated automatically")


# ---------------------------------------------------------------- note budget


def test_identity_notes_stay_within_the_bound_and_collisions_win_the_room():
    from bunnyhole.engine.pi_runtime import MAX_IDENTITY_NOTES, _merge_notes

    base = [f"identity note {i}" for i in range(MAX_IDENTITY_NOTES)]
    merged = _merge_notes(base, ["collision A", "collision B"])
    assert len(merged) == MAX_IDENTITY_NOTES
    assert merged[-3:-1] == ["collision A", "collision B"]
    assert merged[-1] == "+2 more note(s) omitted" or "omitted" in merged[-1]
    assert _merge_notes(base, []) == base
    assert _merge_notes(["a"], ["b"]) == ["a", "b"]
