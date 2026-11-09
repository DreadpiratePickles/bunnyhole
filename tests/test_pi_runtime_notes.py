"""Tests for the PI runtime notes on a live run: identity resolution (U1: notes only; nodes are never merged) and playbook progress and escalation triggers (U2).

Everything is offline. Graph dicts are hand-built, agents are faked with coroutines or ``AsyncMock``.
"""

# Replaces: test_pi_runtime.py (consolidated 2026-11-09).

from __future__ import annotations

import asyncio
from typing import Any, Dict, Optional

import pytest
from pi_helpers import NOW
from pi_helpers import built_engagement as _engagement
from pi_helpers import edge_dict as _ed
from pi_helpers import fake_orchestrator as _orchestrator
from pi_helpers import node_dict as _nd
from pi_helpers import receipt_dict as _rc
from pi_helpers import source_log as _log

from bunnyhole.engine import pi_runtime
from bunnyhole.engine.pi import CaseType, PIBlock, PIEngagement
from bunnyhole.engine.pi_runtime import (
    SOURCE_CLASS_MAP,
    assemble_pi_block,
)

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
