"""One fire and non-fire check per casework signal. Blocks are built by hand. No network."""

from __future__ import annotations

from bunnyhole.engine.pi import (
    CaseType,
    Contradiction,
    CoverageRow,
    Custodian,
    EntityProfile,
    Finding,
    FindingLabel,
    OwnershipBlock,
    OwnershipEdge,
    PIBlock,
    PIEngagement,
    SanctionsScreening,
)
from bunnyhole.engine.pi_analysis import expected_source_classes
from bunnyhole.engine.pi_casework import (
    adverse_media_on_principal,
    asset_with_custodian,
    cfpb_pattern,
    contradiction_dates,
    enforcement_action,
    entity_dissolved_after_claim,
    filings_recent,
    lei_issued,
    lookalike_domain,
    no_asset_hits_after_all_classes_searched,
    nominee_officer_flag,
    officer_or_owner_change_near_judgment,
    offshore_leaks_hit,
    ownership_unresolved_at_nominee,
    pep_flag_on_related,
    registered_agent_only_address,
    registry_active,
    registry_dissolved,
    registry_mismatch,
    sanctions_lists_run_no_hit,
    sanctions_soft_hit_on_related,
    secrecy_jurisdiction_node,
    shell_indicators,
    stable_ownership_window,
    ubo_natural_person_reached,
)


def _engagement() -> PIEngagement:
    return PIEngagement.model_construct(
        engagement_id="pi_signal_test",
        case_type=CaseType.DUE_DILIGENCE,
        purpose="Counterparty review for a filed matter.",
        purpose_category="counterparty_due_diligence",
        subject_is_person=False,
        passive_only=True,
        created_at_utc="2026-01-01T00:00:00+00:00",
    )


def _block(**overrides: object) -> PIBlock:
    payload: dict = {"engagement": _engagement()}
    payload.update(overrides)
    return PIBlock(**payload)


def _finding(node_id: str, label: str, **overrides: object) -> Finding:
    payload: dict = {
        "node_id": node_id,
        "label": label,
        "finding_label": FindingLabel.LEAD,
        "source_count": 1,
        "relevance": "subject",
        "freshness": "unknown",
    }
    payload.update(overrides)
    return Finding(**payload)


def test_registry_active_fires_on_a_live_status_and_not_on_a_dead_one() -> None:
    fired = registry_active(_block(entity_profile=EntityProfile(status="Active")))
    assert fired is not None and "Active" in fired[0] and fired[1] == []
    standing = registry_active(_block(entity_profile=EntityProfile(status="Good standing")))
    assert standing is not None
    assert registry_active(_block(entity_profile=EntityProfile(status="Dissolved"))) is None
    assert registry_active(_block(entity_profile=EntityProfile(status="Inactive"))) is None
    assert registry_active(_block()) is None


def test_registry_dissolved_fires_on_strike_off_and_liquidation() -> None:
    dissolved = registry_dissolved(_block(entity_profile=EntityProfile(status="Dissolved")))
    assert dissolved is not None and "Dissolved" in dissolved[0]
    assert registry_dissolved(_block(entity_profile=EntityProfile(status="Struck off"))) is not None
    assert registry_dissolved(_block(entity_profile=EntityProfile(status="struck-off"))) is not None
    assert registry_dissolved(_block(entity_profile=EntityProfile(status="In liquidation"))) is not None
    assert registry_dissolved(_block(entity_profile=EntityProfile(status="Active"))) is None
    assert registry_dissolved(_block()) is None


def test_lei_issued_quotes_a_non_empty_lei() -> None:
    fired = lei_issued(_block(entity_profile=EntityProfile(lei="549300TESTLEI")))
    assert fired is not None and "549300TESTLEI" in fired[0] and fired[1] == []
    assert lei_issued(_block(entity_profile=EntityProfile(lei="  "))) is None
    assert lei_issued(_block()) is None


def test_filings_recent_needs_a_fresh_subject_filing() -> None:
    fresh = _finding("sec:10-k", "annual report", freshness="fresh", relevance="related")
    assert filings_recent(_block(findings=[fresh])) is not None
    labeled = _finding("company:acme", "Annual filing", freshness="fresh")
    fired = filings_recent(_block(findings=[labeled]))
    assert fired is not None and "company:acme" in fired[1]
    assert filings_recent(_block(findings=[_finding("sec:10-k", "old", freshness="stale")])) is None
    assert filings_recent(_block(findings=[_finding("sec:10-k", "old", freshness="fresh", relevance="unrelated")])) is None


def test_registered_agent_only_address_reads_false_link_reasons() -> None:
    flag = {"node_id": "company:acme", "reason": "shared registered-agent address", "severity": "high"}
    fired = registered_agent_only_address(_block(false_link_flags=[flag]))
    assert fired is not None and fired[1] == ["company:acme"]
    words = {"node_id": "company:beta", "reason": "Registered agent only", "severity": "high"}
    assert registered_agent_only_address(_block(false_link_flags=[words])) is not None
    assert registered_agent_only_address(_block(false_link_flags=[{"node_id": "x", "reason": "shared office"}])) is None


def test_nominee_officer_flag_matches_nominee_reasons_only() -> None:
    flag = {"node_id": "person:nom", "reason": "nominee director on 40 entities", "severity": "high"}
    fired = nominee_officer_flag(_block(false_link_flags=[flag]))
    assert fired is not None and fired[1] == ["person:nom"]
    assert nominee_officer_flag(_block(false_link_flags=[{"node_id": "p", "reason": "director"}])) is None


def test_ownership_unresolved_at_nominee_needs_an_unresolved_node_and_a_marker() -> None:
    flagged = _block(
        ownership=OwnershipBlock(unresolved=["company:nom"]),
        false_link_flags=[{"node_id": "company:nom", "reason": "nominee officer", "severity": "high"}],
    )
    fired = ownership_unresolved_at_nominee(flagged)
    assert fired is not None and fired[1] == ["company:nom"]
    secrecy = _block(ownership=OwnershipBlock(unresolved=["company:haven (secrecy jurisdiction)"]))
    secrecy_hit = ownership_unresolved_at_nominee(secrecy)
    assert secrecy_hit is not None and "company:haven" in secrecy_hit[0]
    assert ownership_unresolved_at_nominee(
        _block(false_link_flags=[{"node_id": "company:nom", "reason": "nominee officer", "severity": "high"}])
    ) is None
    assert ownership_unresolved_at_nominee(_block(ownership=OwnershipBlock(unresolved=["company:plain"]))) is None


def test_ubo_natural_person_reached_needs_edges_and_a_finished_walk() -> None:
    reached = _block(
        ownership=OwnershipBlock(
            levels_walked=1,
            edges=[OwnershipEdge(child="company:acme", parent="person:jane")],
            unresolved=[],
        )
    )
    assert ubo_natural_person_reached(reached) is not None
    assert ubo_natural_person_reached(_block()) is None
    unfinished = _block(
        ownership=OwnershipBlock(
            levels_walked=1,
            edges=[OwnershipEdge(child="company:acme", parent="company:top")],
            unresolved=["company:top"],
        )
    )
    assert ubo_natural_person_reached(unfinished) is None
    shallow = _block(
        ownership=OwnershipBlock(
            levels_walked=0,
            edges=[OwnershipEdge(child="company:acme", parent="person:jane")],
        )
    )
    assert ubo_natural_person_reached(shallow) is None


def test_sanctions_soft_hit_on_related_uses_relevance_or_graph_match() -> None:
    related = {"list": "OFAC SDN", "name": "Acme", "relevance": "related", "node_id": "sanction:1"}
    fired = sanctions_soft_hit_on_related(_block(sanctions=SanctionsScreening(hits=[related])))
    assert fired is not None and "OFAC SDN" in fired[0] and "Acme" in fired[0] and fired[1] == ["sanction:1"]
    graphed = {"list": "OFAC SDN", "name": "Acme", "relevance": "subject", "graph_match": True}
    assert sanctions_soft_hit_on_related(_block(sanctions=SanctionsScreening(hits=[graphed]))) is not None
    subject = {"list": "OFAC SDN", "name": "Acme", "relevance": "subject", "graph_match": False}
    assert sanctions_soft_hit_on_related(_block(sanctions=SanctionsScreening(hits=[subject]))) is None
    assert sanctions_soft_hit_on_related(_block()) is None


def test_pep_flag_on_related_reads_hits_and_identity_notes() -> None:
    hit = {"list": "OFAC PEP", "match": "name", "name": "Jane", "relevance": "related", "node_id": "person:jane"}
    fired = pep_flag_on_related(_block(sanctions=SanctionsScreening(hits=[hit])))
    assert fired is not None and "person:jane" in fired[1]
    noted = pep_flag_on_related(_block(identity_notes=["PEP record for a related party"]))
    assert noted is not None and "related" in noted[0]
    subject = {"list": "OFAC PEP", "match": "name", "name": "Jane", "relevance": "subject"}
    assert pep_flag_on_related(_block(sanctions=SanctionsScreening(hits=[subject]))) is None
    assert pep_flag_on_related(_block(identity_notes=["PEP record with no other context"])) is None


def test_adverse_media_on_principal_is_an_article_or_an_adverse_label() -> None:
    article = _finding("article:1", "Profile of the principal", relevance="subject")
    fired = adverse_media_on_principal(_block(findings=[article]))
    assert fired is not None and fired[1] == ["article:1"]
    labeled = _finding("news:1", "Adverse media note", relevance="related")
    assert adverse_media_on_principal(_block(findings=[labeled])) is not None
    unrelated = _finding("article:2", "Other story", relevance="unrelated")
    assert adverse_media_on_principal(_block(findings=[unrelated])) is None
    assert adverse_media_on_principal(_block(findings=[_finding("news:2", "Market note")])) is None


def test_sanctions_lists_run_no_hit_requires_a_finished_screen_with_no_hits() -> None:
    clear = sanctions_lists_run_no_hit(_block(sanctions=SanctionsScreening(status="lists_run", hits=[])))
    assert clear is not None and clear[1] == []
    hit = {"list": "OFAC SDN", "name": "Acme"}
    assert sanctions_lists_run_no_hit(_block(sanctions=SanctionsScreening(status="lists_run", hits=[hit]))) is None
    assert sanctions_lists_run_no_hit(_block(sanctions=SanctionsScreening(status="not_run", hits=[]))) is None
    assert sanctions_lists_run_no_hit(_block(sanctions=SanctionsScreening(status="partial", hits=[]))) is None


def test_secrecy_jurisdiction_node_reads_the_profile_or_a_secrecy_note() -> None:
    coded = secrecy_jurisdiction_node(_block(entity_profile=EntityProfile(jurisdiction="KY")))
    assert coded is not None and "KY" in coded[0]
    dashed = secrecy_jurisdiction_node(_block(entity_profile=EntityProfile(jurisdiction="VG-something")))
    assert dashed is not None
    noted = secrecy_jurisdiction_node(
        _block(false_link_flags=[{"node_id": "company:haven", "reason": "secrecy jurisdiction", "severity": "high"}])
    )
    assert noted is not None and "company:haven" in noted[1]
    assert secrecy_jurisdiction_node(_block(entity_profile=EntityProfile(jurisdiction="US"))) is None
    assert secrecy_jurisdiction_node(_block(entity_profile=EntityProfile(jurisdiction="Cayman Islands"))) is None


def test_offshore_leaks_hit_ignores_unrelated_nodes() -> None:
    hit = _finding("icij:1", "Offshore leaks officer", relevance="related")
    fired = offshore_leaks_hit(_block(findings=[hit]))
    assert fired is not None and fired[1] == ["icij:1"]
    assert offshore_leaks_hit(_block(findings=[_finding("icij:2", "Offshore", relevance="unrelated")])) is None
    assert offshore_leaks_hit(_block(findings=[_finding("company:acme", "Acme Ltd")])) is None


def test_officer_or_owner_change_near_judgment_needs_both_halves() -> None:
    change = Contradiction(kind="role", description="Owner changed just before judgment", node_ids=["company:acme"])
    fired = officer_or_owner_change_near_judgment(_block(contradictions=[change]))
    assert fired is not None and fired[1] == ["company:acme"]
    role_only = Contradiction(kind="role", description="Owner changed last year")
    assert officer_or_owner_change_near_judgment(_block(contradictions=[role_only])) is None
    assert officer_or_owner_change_near_judgment(_block()) is None


def test_entity_dissolved_after_claim_needs_both_facts() -> None:
    block = _block(
        entity_profile=EntityProfile(status="Dissolved"),
        evidence_gaps=["No record of the claim's asset trail"],
    )
    assert entity_dissolved_after_claim(block) is not None
    claim = Contradiction(kind="timeline", description="Dissolution followed the claim", node_ids=["company:acme"])
    fired = entity_dissolved_after_claim(
        _block(entity_profile=EntityProfile(status="Dissolved"), contradictions=[claim])
    )
    assert fired is not None and "company:acme" in fired[1]
    assert entity_dissolved_after_claim(_block(entity_profile=EntityProfile(status="Dissolved"))) is None
    assert entity_dissolved_after_claim(_block(evidence_gaps=["open claim"])) is None


def test_contradiction_dates_matches_kind_or_description() -> None:
    dated = Contradiction(kind="date_conflict", description="Filings disagree", node_ids=["company:acme"])
    fired = contradiction_dates(_block(contradictions=[dated]))
    assert fired is not None and fired[1] == ["company:acme"]
    described = Contradiction(kind="timeline", description="The date of incorporation conflicts")
    assert contradiction_dates(_block(contradictions=[described])) is not None
    assert contradiction_dates(_block(contradictions=[Contradiction(kind="name", description="Two names")])) is None


def test_stable_ownership_window_is_edges_without_gaps_or_contradictions() -> None:
    stable = _block(
        ownership=OwnershipBlock(
            levels_walked=1,
            edges=[OwnershipEdge(child="company:acme", parent="person:jane")],
        )
    )
    assert stable_ownership_window(stable) is not None
    contested = _block(
        ownership=OwnershipBlock(edges=[OwnershipEdge(child="company:acme", parent="person:jane")]),
        contradictions=[Contradiction(kind="name", description="Two names")],
    )
    assert stable_ownership_window(contested) is None
    assert stable_ownership_window(_block()) is None


def test_no_asset_hits_after_all_classes_searched_needs_a_full_empty_sweep() -> None:
    coverage = [
        CoverageRow(source_class=name, searched=True, outcome="negative")
        for name in expected_source_classes(CaseType.ASSET_SEARCH, subject_is_person=False)
    ]
    assert no_asset_hits_after_all_classes_searched(_block(coverage=coverage)) is not None
    assert no_asset_hits_after_all_classes_searched(_block(coverage=coverage[:-1])) is None
    custodian = Custodian(finding="wallet:abc", custodian="Example Exchange", instrument="subpoena", jurisdiction="us")
    assert no_asset_hits_after_all_classes_searched(_block(coverage=coverage, custodians=[custodian])) is None
    wallet = _finding("wallet:abc", "deposit address")
    assert no_asset_hits_after_all_classes_searched(_block(coverage=coverage, findings=[wallet])) is None


def test_asset_with_custodian_names_the_custodian_and_the_finding() -> None:
    custodian = Custodian(
        finding="wallet:abc deposit",
        custodian="Example Exchange",
        instrument="subpoena",
        jurisdiction="us",
        note="cash-out point",
    )
    fired = asset_with_custodian(_block(custodians=[custodian]))
    assert fired is not None
    assert "Example Exchange" in fired[0] and "wallet:abc deposit" in fired[0]
    assert asset_with_custodian(_block()) is None


def test_cfpb_pattern_matches_complaints_that_are_not_unrelated() -> None:
    complaint = _finding("cfpb:1", "CFPB complaint pattern", relevance="related")
    fired = cfpb_pattern(_block(findings=[complaint]))
    assert fired is not None and fired[1] == ["cfpb:1"]
    unrelated = _finding("cfpb:2", "CFPB complaint", relevance="unrelated")
    assert cfpb_pattern(_block(findings=[unrelated])) is None
    assert cfpb_pattern(_block(findings=[_finding("news:1", "Quiet quarter")])) is None


def test_enforcement_action_matches_orders_and_sec_nodes() -> None:
    order = _finding("court:1", "Consent order", relevance="subject")
    assert enforcement_action(_block(findings=[order])) is not None
    filing = _finding("sec:aaer", "press release", relevance="related")
    fired = enforcement_action(_block(findings=[filing]))
    assert fired is not None and "sec:aaer" in fired[1]
    unrelated = _finding("sec:other", "filing", relevance="unrelated")
    assert enforcement_action(_block(findings=[unrelated])) is None
    assert enforcement_action(_block(findings=[_finding("news:1", "Profile")])) is None


def test_lookalike_domain_is_a_typosquat_or_a_similar_domain() -> None:
    named = _finding("domain:acme-inc.test", "Lookalike of the subject")
    assert lookalike_domain(_block(findings=[named])) is not None
    similar = _finding("domain:acme.test", "Similar spelling")
    fired = lookalike_domain(_block(findings=[similar]))
    assert fired is not None and fired[1] == ["domain:acme.test"]
    plain = _finding("domain:acme.test", "Registrant record")
    assert lookalike_domain(_block(findings=[plain])) is None
    assert lookalike_domain(_block(findings=[_finding("company:acme", "Acme Ltd")])) is None


def test_shell_indicators_fire_when_any_shell_signal_fires() -> None:
    flag = {"node_id": "person:nom", "reason": "nominee director", "severity": "high"}
    fired = shell_indicators(_block(false_link_flags=[flag]))
    assert fired is not None and "person:nom" in fired[1]
    assert shell_indicators(_block()) is None


def test_registry_mismatch_reads_contradiction_text() -> None:
    mismatch = Contradiction(kind="registry", description="Status differs", node_ids=["lei:1"])
    fired = registry_mismatch(_block(contradictions=[mismatch]))
    assert fired is not None and fired[1] == ["lei:1"]
    word = Contradiction(kind="identity", description="Name mismatch")
    assert registry_mismatch(_block(contradictions=[word])) is not None
    assert registry_mismatch(_block(contradictions=[Contradiction(kind="name", description="Two names")])) is None
