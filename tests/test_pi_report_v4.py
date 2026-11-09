"""Fourth pass on the PI report (final-verifier findings P1, P3, P4, P5, P7, P8).

Pure and deterministic. Blocks are built by direct ``PIBlock`` construction (no purpose gates involved), mirroring
the two live reports: a Bombardier-like block (partial screening, TSX-listed, custodian trigger fired by the
playbook for every entity) and a Rosneft-like block (soft sanctions hits, unresolved parent, raw node ids in
the trigger text).
"""

from __future__ import annotations

import re
from typing import Any, Dict

from bunnyhole.engine.pi import (
    CaseType,
    Contradiction,
    CoverageRow,
    EntityProfile,
    EscalationTrigger,
    Finding,
    FindingLabel,
    OwnershipBlock,
    OwnershipEdge,
    PIBlock,
    PIEngagement,
    SanctionsScreening,
)
from bunnyhole.engine.pi_report import build_pi_report
from bunnyhole.engine.pi_report_common import truncate_words

EU_ENTRY = "EU Consolidated List: not automated (verify at https://www.sanctionsmap.eu/)"
SANCTIONS_TRIGGER = "A sanctions hit, 50% rule block or PEP link: refer to compliance counsel."
NOMINEE_TRIGGER = "The ownership chain ends at a nominee or secrecy jurisdiction."
CUSTODIAN_TRIGGER = "Non-public company records are needed: counsel for a production order."
BULLET_LABELS = ["Sanctions", "Registry", "Findings", "Biggest gap", "Not covered", "Next step"]


def _engagement(**overrides: Any) -> PIEngagement:
    fields: Dict[str, Any] = {
        "engagement_id": "pi_74e9482909", "case_type": CaseType.DUE_DILIGENCE,
        "purpose": "Counterparty due diligence ahead of a supply contract", "subject_is_person": False,
        "created_at_utc": "2026-11-09T07:48:55+00:00",
    }
    fields.update(overrides)
    return PIEngagement(**fields)


def _block(**overrides: Any) -> PIBlock:
    fields: Dict[str, Any] = {"engagement": _engagement()}
    fields.update(overrides)
    return PIBlock(**fields)


def _render(block: PIBlock, **extra: Any) -> str:
    result: Dict[str, Any] = dict(extra)
    result["pi"] = block.model_dump(mode="json")
    return build_pi_report(result)


def _sections(markdown: str) -> Dict[str, str]:
    parts = re.split(r"^## (.+)$", markdown, flags=re.MULTILINE)
    return {parts[i].strip(): parts[i + 1].strip() for i in range(1, len(parts), 2)}


def _bullets(markdown: str) -> Dict[str, str]:
    """{label: text} of the Bottom line bullets (each is one line `- **Label:** text`)."""
    found: Dict[str, str] = {}
    for line in _sections(markdown)["Bottom line"].splitlines():
        match = re.match(r"^- \*\*(?P<label>[^*]+):\*\* (?P<text>.*)$", line)
        assert match, f"not a labelled bullet: {line!r}"
        found[match.group("label")] = match.group("text")
    return found


def _lead(node_id: str, label: str, relevance: str = "subject", **kw: Any) -> Finding:
    return Finding(node_id=node_id, label=label, finding_label=kw.pop("finding_label", FindingLabel.LEAD),
                   source_count=kw.pop("source_count", 1), relevance=relevance, **kw)


def _tsx_listed_block(**overrides: Any) -> PIBlock:
    """Bombardier-like: a registry profile, nothing sanctioned, the custodian trigger fired by the playbook."""
    fields: Dict[str, Any] = {
        "findings": [_lead("lei:W7L3", "BOMBARDIER INC. (CA-QC)"), _lead("article:1", "News: Bombardier wins an order",
                                                                           "related")],
        "entity_profile": EntityProfile(legal_name="BOMBARDIER INC.", lei="W7L3VLU8EHQY34Z36697", status="ACTIVE",
                                        jurisdiction="CA-QC"),
        "sanctions": SanctionsScreening(status="partial", screened=["Canada SEMA", "OFAC SDN"],
                                        not_screened=["OpenSanctions (skipped: HTTP 401)", EU_ENTRY]),
        "escalation_triggers": [
            EscalationTrigger(trigger=SANCTIONS_TRIGGER, fired=False, why="not fired on the lists screened"),
            EscalationTrigger(trigger=NOMINEE_TRIGGER, fired=False, why="no unresolved ownership node"),
            EscalationTrigger(trigger=CUSTODIAN_TRIGGER, fired=True, why="custodian-bearing finding(s): records"),
        ],
        "handoff_sheet": ["Confirm corporate status and beneficial ownership on the primary registry: X"],
    }
    fields.update(overrides)
    return _block(**fields)


# ---------------------------------------------------------------- truncate_words


def test_truncate_words_cuts_at_a_word_boundary_with_an_ellipsis():
    text = "verify on the primary list before relying on it and then some more words"
    cut = truncate_words(text, 30)
    assert cut.endswith("…") and len(cut) <= 30
    assert text.startswith(cut[:-1].rstrip())
    assert text[len(cut[:-1].rstrip())] == " "  # the cut fell on a space, never inside a word


def test_truncate_words_leaves_short_text_alone_and_never_ends_on_a_lone_backslash():
    assert truncate_words("short", 30) == "short"
    cut = truncate_words("\\[" * 40, 11)
    assert cut.endswith("…") and not cut[:-1].endswith("\\")


# ---------------------------------------------------------------- P3: bottom line as a short labelled list


def test_bottom_line_is_a_short_list_of_labelled_one_line_bullets_in_a_fixed_order():
    markdown = _render(_tsx_listed_block())
    bullets = _bullets(markdown)
    labels = list(bullets)
    assert 3 <= len(labels) <= 6
    assert labels == [label for label in BULLET_LABELS if label in labels]  # fixed order
    assert labels[0] == "Sanctions"
    for line in _sections(markdown)["Bottom line"].splitlines():
        assert line.startswith("- **") and len(line) <= 220, line


def test_every_bullet_stays_within_220_characters_even_with_long_inputs():
    long_name = "OPEN JOINT-STOCK COMPANY ROSNEFT OIL COMPANY " * 3
    block = _block(
        findings=[_lead("n1", long_name), _lead("n2", "Another " + long_name)],
        sanctions=SanctionsScreening(
            status="partial", screened=["Canada SEMA", "OFAC SDN", "UN Consolidated List", "UK Sanctions List"],
            not_screened=["OpenSanctions (skipped: HTTP 401 from api.opensanctions.org needs a key)", EU_ENTRY],
            hits=[{"list": "UK Sanctions List", "name": long_name, "node_id": "n1"},
                  {"list": "OFAC SDN", "name": "Another " + long_name, "node_id": "n2"},
                  {"list": "Canada SEMA", "name": "Third " + long_name, "node_id": "n3"}]),
        entity_profile=EntityProfile(legal_name=long_name, lei="253400JT3MQWNDKMJE44", status="ACTIVE",
                                     jurisdiction="RU", parents=["Reporting exception: NO_KNOWN_PERSON (GLEIF: no known "
                                                                 "ultimate parent)"]),
        ownership=OwnershipBlock(levels_walked=1, unresolved=["lei:253400JT3MQWNDKMJE44"],
                                 blocked_by_50_rule=["n1", "n2", "n3", "n4"]),
        coverage=[CoverageRow(source_class=f"class_{i}", searched=False, outcome="not_searched") for i in range(6)],
        escalation_triggers=[EscalationTrigger(trigger=SANCTIONS_TRIGGER, fired=True, why="word " * 80)] * 3,
    )
    for line in _sections(_render(block))["Bottom line"].splitlines():
        assert len(line) <= 220, (len(line), line)


def test_truncated_bullets_end_in_an_ellipsis_after_a_whole_word():
    why = " ".join(f"evidence{i}" for i in range(60))
    block = _tsx_listed_block(escalation_triggers=[EscalationTrigger(trigger=SANCTIONS_TRIGGER, fired=True, why=why)])
    step = _bullets(_render(block))["Next step"]
    assert "…" in step and len(step) <= 220 - len("- **Next step:** ")
    last_word = step.split("…")[0].rsplit(" ", 1)[-1]
    assert last_word in why.split(), last_word  # a complete word of the why text, never a cut one


def test_no_raw_sanction_or_document_node_ids_appear_in_the_bottom_line_when_a_label_is_known():
    block = _block(
        findings=[_lead("sanction:ca:1_part_2-821-rosneft_pjsc", "⛔ Rosneft PJSC"),
                  _lead("sanction:ofac:17022", "OPEN JOINT-STOCK COMPANY ROSNEFT OIL COMPANY")],
        sanctions=SanctionsScreening(status="partial", screened=["Canada SEMA"], not_screened=[EU_ENTRY],
                                     hits=[{"list": "Canada SEMA", "name": "Rosneft PJSC",
                                            "node_id": "sanction:ca:1_part_2-821-rosneft_pjsc"}]),
        ownership=OwnershipBlock(levels_walked=1, unresolved=["sanction:ofac:17022"]),
        escalation_triggers=[EscalationTrigger(
            trigger=SANCTIONS_TRIGGER, fired=True,
            why="sanctions/PEP listing on sanction:ca:1_part_2-821-rosneft_pjsc, sanction:ofac:17022 (soft name match)")],
    )
    bottom = _sections(_render(block))["Bottom line"]
    assert "sanction:ca:" not in bottom and "sanction:ofac:" not in bottom
    assert "Rosneft PJSC" in bottom


def test_an_unknown_node_id_is_shortened_not_dropped():
    block = _block(escalation_triggers=[EscalationTrigger(
        trigger=SANCTIONS_TRIGGER, fired=True, why="listing on sanction:zz:" + "x" * 60)])
    step = _bullets(_render(block))["Next step"]
    assert "x" * 60 not in step and "sanction:zz" in step


def test_registry_identifiers_keep_their_label_and_id():
    block = _block(ownership=OwnershipBlock(levels_walked=1, unresolved=["lei:X1"]))
    markdown = build_pi_report({"pi": block.model_dump(mode="json"),
                                "nodes": [{"id": "lei:X1", "label": "\U0001f451 Acme Parent Ltd (RU)"}]})
    assert "ownership unresolved at Acme Parent Ltd (RU) (lei:X1)" in _bullets(markdown)["Biggest gap"]


def test_biggest_gap_is_one_item_and_the_rest_are_counted():
    block = _block(
        ownership=OwnershipBlock(levels_walked=1, unresolved=["lei:UNRESOLVED-1"]),
        coverage=[CoverageRow(source_class="property_assets", searched=False, outcome="not_searched")],
    )
    bullets = _bullets(_render(block))
    assert bullets["Biggest gap"].startswith("ownership unresolved at lei:UNRESOLVED-1")
    assert "property_assets" in bullets["Not covered"] and "not searched" in bullets["Not covered"]


def test_not_covered_names_unsearched_classes_and_partial_coverage_and_is_absent_when_everything_ran():
    block = _block(coverage=[
        CoverageRow(source_class="beneficial_ownership", searched=False, outcome="not_searched"),
        CoverageRow(source_class="sanctions_pep", searched=True, sources=["ofac_sdn"], skipped=["opensanctions"],
                    outcome="negative"),
    ])
    text = _bullets(_render(block))["Not covered"]
    assert "beneficial_ownership" in text and "sanctions_pep" in text and "opensanctions" in text
    ran = _block(coverage=[CoverageRow(source_class="sanctions_pep", searched=True, sources=["ofac_sdn"],
                                       outcome="negative")])
    assert "Not covered" not in _bullets(_render(ran))


def test_a_sanctions_hit_leads_with_a_soft_match_and_the_unscreened_lists_move_to_not_covered():
    block = _block(sanctions=SanctionsScreening(
        status="partial", screened=["Canada SEMA"], not_screened=["OpenSanctions (HTTP 401)", EU_ENTRY],
        hits=[{"list": "Canada SEMA", "name": "ROSNEFT OIL COMPANY", "node_id": "n1"}]))
    bullets = _bullets(_render(block))
    assert bullets["Sanctions"].startswith("soft name match to ROSNEFT OIL COMPANY on Canada SEMA; verify on the primary")
    assert "sanctions lists NOT screened: OpenSanctions, EU Consolidated List" in bullets["Not covered"]


def test_without_a_hit_the_sanctions_bullet_names_the_lists_that_did_not_run():
    block = _block(sanctions=SanctionsScreening(
        status="partial", screened=["Canada SEMA"], not_screened=["OpenSanctions (HTTP 401)", EU_ENTRY]))
    bullets = _bullets(_render(block))
    assert "NOT screened: OpenSanctions, EU Consolidated List" in bullets["Sanctions"]
    assert "Not covered" not in bullets  # not repeated there


def test_a_blocked_by_the_50_percent_rule_flag_survives_long_hit_names():
    long_name = "OPEN JOINT-STOCK COMPANY ROSNEFT OIL COMPANY"
    block = _block(
        sanctions=SanctionsScreening(
            status="partial", screened=["UK Sanctions List", "OFAC SDN", "Canada SEMA"],
            not_screened=[EU_ENTRY],
            hits=[{"list": "UK Sanctions List", "name": long_name, "node_id": "a"},
                  {"list": "OFAC SDN", "name": "PJSC Rosneft Oil Company", "node_id": "b"},
                  {"list": "Canada SEMA", "name": "Rosneft PJSC", "node_id": "c"}]),
        ownership=OwnershipBlock(levels_walked=1, blocked_by_50_rule=["lei:BLOCKED0000000000001"]),
    )
    text = _bullets(_render(block))["Sanctions"]
    assert "50% rule" in text and "lei:BLOCKED0000000000001" in text
    assert text.startswith("soft name match to")


# ---------------------------------------------------------------- P1: the EU list in the report


def test_the_bottom_line_the_section_and_the_trigger_name_the_eu_list():
    block = _tsx_listed_block()
    markdown = _render(block)
    assert "EU Consolidated List" in _bullets(markdown)["Sanctions"]
    section = _sections(markdown)["Sanctions screening"]
    assert "| EU Consolidated List | not automated (verify at https://www.sanctionsmap.eu/) |" in section


def test_the_eu_list_is_named_even_when_all_five_automated_lists_ran():
    block = _block(sanctions=SanctionsScreening(
        status="lists_run", screened=["Canada SEMA", "OpenSanctions", "OFAC SDN", "UN Consolidated List",
                                      "UK Sanctions List"], not_screened=[EU_ENTRY]))
    markdown = _render(block)
    assert "lists_run" in _bullets(markdown)["Sanctions"]
    assert "NOT screened: EU Consolidated List" in _bullets(markdown)["Sanctions"]
    assert "EU Consolidated List" in _sections(markdown)["Sanctions screening"]


def test_a_reason_in_parentheses_keeps_its_closing_bracket_in_the_section_table():
    section = _sections(_render(_tsx_listed_block()))["Sanctions screening"]
    row = next(line for line in section.splitlines() if "EU Consolidated List" in line)
    assert row.count("(") == row.count(")")


# ---------------------------------------------------------------- P4: the custodian trigger is not the next step


def test_the_custodian_trigger_is_not_the_next_step_for_an_entity_due_diligence():
    step = _bullets(_render(_tsx_listed_block()))["Next step"]
    assert "production order" not in step and "counsel" not in step
    assert step.startswith("No escalation indicated on the public record; to go further order the registry filings")
    assert "Registraire des entreprises du Qu" in step  # registry chosen from the profile jurisdiction CA-QC


def test_the_registry_comes_from_the_engagement_jurisdiction_when_there_is_no_profile():
    block = _tsx_listed_block(entity_profile=None, engagement=_engagement(jurisdiction="uk"))
    assert "Companies House" in _bullets(_render(block))["Next step"]


def test_a_fired_sanctions_trigger_wins_over_everything():
    block = _tsx_listed_block(escalation_triggers=[
        EscalationTrigger(trigger="Some other trigger", fired=True, why="other"),
        EscalationTrigger(trigger=CUSTODIAN_TRIGGER, fired=True, why="custodian"),
        EscalationTrigger(trigger=SANCTIONS_TRIGGER, fired=True, why="Canada SEMA soft name match"),
    ])
    step = _bullets(_render(block))["Next step"]
    assert step.startswith("escalate, trigger fired: A sanctions hit, 50% rule block or PEP link")
    assert "Canada SEMA soft name match" in step
    assert "further fired trigger" in step


def test_a_fired_nominee_trigger_counts_with_the_sanctions_family():
    block = _tsx_listed_block(escalation_triggers=[
        EscalationTrigger(trigger="Some other trigger", fired=True, why="other"),
        EscalationTrigger(trigger=NOMINEE_TRIGGER, fired=True, why="nominee director"),
    ])
    assert "ends at a nominee" in _bullets(_render(block))["Next step"]


def test_another_fired_trigger_beats_the_custodian_trigger():
    block = _tsx_listed_block(escalation_triggers=[
        EscalationTrigger(trigger=CUSTODIAN_TRIGGER, fired=True, why="custodian"),
        EscalationTrigger(trigger="Some other trigger", fired=True, why="because"),
    ])
    step = _bullets(_render(block))["Next step"]
    assert step.startswith("escalate, trigger fired: Some other trigger (because)")
    assert "production order" not in step


def test_the_custodian_trigger_stays_a_valid_next_step_for_asset_search_and_fraud_screen():
    for case_type in (CaseType.ASSET_SEARCH, CaseType.FRAUD_SCREEN):
        block = _tsx_listed_block(engagement=_engagement(case_type=case_type), escalation_triggers=[
            EscalationTrigger(trigger=CUSTODIAN_TRIGGER, fired=True, why="custodian-bearing finding(s): records")])
        step = _bullets(_render(block))["Next step"]
        assert step.startswith("escalate, trigger fired: Non-public company records are needed"), case_type


def test_a_person_subject_keeps_the_old_next_step_order():
    block = _block(
        engagement=_engagement(case_type=CaseType.BACKGROUND, subject_is_person=True),
        escalation_triggers=[EscalationTrigger(trigger=CUSTODIAN_TRIGGER, fired=True, why="custodian")],
    )
    assert _bullets(_render(block))["Next step"].startswith("escalate, trigger fired: Non-public company records")


# ---------------------------------------------------------------- P5: the same population as the bottom line


def test_findings_bullet_and_section_count_the_same_relevant_findings():
    findings = [_lead(f"n{i}", f"Subject record {i}") for i in range(3)] + [
        _lead(f"u{i}", f"Unknown record {i}", "unknown") for i in range(3)]
    markdown = _render(_block(findings=findings))
    assert "3 relevant (3 lead)" in _bullets(markdown)["Findings"]
    assert "3 unrelated or low-relevance records were set aside" in _bullets(markdown)["Findings"]


# ---------------------------------------------------------------- P7: no bare filler


def test_empty_false_link_and_contradiction_sections_say_what_none_means():
    sections = _sections(_render(_block()))
    for heading in ("What is NOT a link", "Contradictions and gaps"):
        text = sections[heading]
        assert text.startswith("None.") and text != "None.", heading
        assert "not proof that none exist" in text, heading


def test_populated_false_link_and_contradiction_sections_do_not_get_the_filler():
    block = _block(false_link_flags=[{"node_id": "n1", "reason": "registered agent", "severity": "high"}],
                   contradictions=[Contradiction(kind="k", description="d")])
    sections = _sections(_render(block))
    assert "not proof that none exist" not in sections["What is NOT a link"]
    assert "not proof that none exist" not in sections["Contradictions and gaps"]


# ---------------------------------------------------------------- P8: set aside but possibly relevant


def _set_aside_block(**overrides: Any) -> PIBlock:
    fields: Dict[str, Any] = {
        "findings": [
            _lead("lei:253400JT3MQWNDKMJE44", "PJSC Rosneft Oil Company"),
            _lead("sec:1", "SEC Form 20-F: BP PLC (BP, BPAQF) (CIK 0000313807)", "unrelated"),
            _lead("hn:1", "HN (@x): BP to Exit Its 20% Shareholding in Russian Oil P...", "unrelated"),
            _lead("ein:1", "501(c)(3): Rosfest Inc (Sarasota, FL)", "unrelated"),
        ],
        "entity_profile": EntityProfile(legal_name="PJSC Rosneft Oil Company", parents=["BP PLC"]),
    }
    fields.update(overrides)
    return _block(**fields)


def test_unrelated_records_that_mention_a_known_parent_are_listed_as_possibly_relevant():
    section = _sections(_render(_set_aside_block()))["Findings"]
    assert "Set aside but possibly relevant (mentions a related party):" in section
    tail = section.split("Set aside but possibly relevant (mentions a related party):")[1]
    assert "SEC Form 20-F: BP PLC" in tail and "BP to Exit Its 20% Shareholding" in tail
    assert "Rosfest" not in tail


def test_related_parties_also_come_from_the_ownership_edges():
    block = _set_aside_block(
        entity_profile=None,
        ownership=OwnershipBlock(levels_walked=1, edges=[
            OwnershipEdge(child="lei:253400JT3MQWNDKMJE44", parent="lei:BPPARENT00000000001")]),
    )
    markdown = build_pi_report({"pi": block.model_dump(mode="json"),
                                "nodes": [{"id": "lei:BPPARENT00000000001", "label": "BP PLC (GB)"}]})
    assert "Set aside but possibly relevant" in _sections(markdown)["Findings"]


def test_the_possibly_relevant_list_is_capped_at_five_and_unrelated_noise_is_not_listed():
    extra = [_lead(f"sec:{i}", f"SEC Form 6-K: BP PLC filing {i}", "unrelated") for i in range(10)]
    block = _set_aside_block(findings=_set_aside_block().findings + extra)
    tail = _sections(_render(block))["Findings"].split("Set aside but possibly relevant (mentions a related party):")[1]
    assert len(re.findall(r"\(mentions BP PLC\)", tail.split("\n\n")[0])) == 5
    quiet = _set_aside_block(entity_profile=None)
    assert "possibly relevant" not in _sections(_render(quiet))["Findings"]


def test_a_short_name_must_match_a_whole_word_not_a_substring():
    block = _set_aside_block(findings=[_lead("n1", "Subject"), _lead("x", "Bpmn tooling guide", "unrelated")])
    assert "possibly relevant" not in _sections(_render(block))["Findings"]


# ---------------------------------------------------------------- short registry names for the next step


def test_registry_short_names_follow_the_same_routing_as_the_full_registry_text():
    from bunnyhole.engine.pi_escalation import registry_short_for

    assert registry_short_for("GB") == registry_short_for("uk") == "Companies House"
    assert registry_short_for("CA-QC").startswith("Registraire des entreprises du Qu")
    assert registry_short_for("us-de") == registry_short_for("US") == "the state Secretary of State business registry"
    assert "(XX)" in registry_short_for("XX")
    assert registry_short_for("") == "the company registry of the jurisdiction of incorporation"
    assert max(len(registry_short_for(code)) for code in ("gb", "ca-qc", "ca-on", "ca", "ru", "us")) <= 60
