"""Quality-upgrade tests for the PI report builder: sanctions-first bottom line, relevance filtering, entity
profile, sanctions screening section, falsifier collapse, Markdown hygiene, and the ACH sanctions note.

Pure and deterministic: no network, no model calls. Fixtures are built by hand to mirror the first two live
reports (a Rosneft-like block with a soft Canadian sanctions hit and partial screening, and a Bombardier-like
block with no hits, partial screening and tied single-source leads).
"""

from __future__ import annotations

import re
from typing import Any, Dict, List

from bunnyhole.engine.pi import (
    CaseType,
    Contradiction,
    CoverageRow,
    Custodian,
    EntityProfile,
    EscalationTrigger,
    Finding,
    FindingLabel,
    OwnershipBlock,
    PIBlock,
    PIEngagement,
    SanctionsScreening,
)
from bunnyhole.engine.pi_report import build_pi_report

SOFT_HIT_SENTENCE = "verify on the primary list before relying on it"
LEAD_SENTENCE_START = "A second independent source that contradicts, or corroborates, the single-source lead "
NAME_MATCH_SENTENCE = "A name match on a sanctions list is a lead, not a determination."
ACH_NOTE = "Note: sanctions screening returned a soft hit; the ACH assessment does not consider sanctions lists."
NO_ANOMALY_VERDICT = (
    "Current evidence primarily reflects standard regulatory, infrastructure, or public-record footprint "
    "without deterministic cross-domain attribution anomalies."
)


# ------------------------------------------------------------------ fixtures and helpers


def _engagement(**overrides: Any) -> PIEngagement:
    fields: Dict[str, Any] = {
        "engagement_id": "pi_74e9482909",
        "case_type": CaseType.DUE_DILIGENCE,
        "purpose": "Counterparty due diligence ahead of a supply contract",
        "subject_is_person": False,
        "created_at_utc": "2026-11-09T07:48:55+00:00",
    }
    fields.update(overrides)
    return PIEngagement(**fields)


def _block(**overrides: Any) -> PIBlock:
    fields: Dict[str, Any] = {"engagement": _engagement()}
    fields.update(overrides)
    return PIBlock(**fields)


def _result(block: PIBlock, **extra: Any) -> Dict[str, Any]:
    result: Dict[str, Any] = dict(extra)
    result["pi"] = block.model_dump(mode="json")
    return result


def _render(block: PIBlock, **extra: Any) -> str:
    return build_pi_report(_result(block, **extra))


def _sections(markdown: str) -> Dict[str, str]:
    parts = re.split(r"^## (.+)$", markdown, flags=re.MULTILINE)
    return {parts[i].strip(): parts[i + 1].strip() for i in range(1, len(parts), 2)}


def _h2(markdown: str) -> List[str]:
    return re.findall(r"^## (.+)$", markdown, flags=re.MULTILINE)


def _bottom(markdown: str) -> str:
    return _sections(markdown)["Bottom line"]


def _sentences(text: str) -> List[str]:
    return re.split(r"(?<=[.!?])\s+(?=[A-Z0-9])", text)


def _bullet(markdown: str, label: str) -> str:
    """Text of one Bottom line bullet (``- **Label:** text``); empty when that bullet is absent.

    Requirement change (2026-11-09, final-verifier P3): the Bottom line is a labelled list, not a paragraph.
    """
    prefix = f"- **{label}:** "
    return next((line[len(prefix):] for line in _bottom(markdown).splitlines() if line.startswith(prefix)), "")


def _unescaped_pipes(line: str) -> int:
    return len(re.findall(r"(?<!\\)\|", line))


def _lead(node_id: str, label: str, relevance: str = "unknown", reason: str = "", **kw: Any) -> Finding:
    return Finding(
        node_id=node_id,
        label=label,
        finding_label=kw.pop("finding_label", FindingLabel.LEAD),
        source_count=kw.pop("source_count", 1),
        relevance=relevance,
        relevance_reason=reason,
        **kw,
    )


def _rosneft_block() -> PIBlock:
    findings = [
        _lead("lei:253400JT3MQWNDKMJE44", "PJSC Rosneft Oil Company", "subject", "GLEIF legal-name match"),
        _lead("wikidata:Q118611133", "Rosneft Deutschland", "related", "subsidiary named in the registry parent link"),
        _lead("article:1", "Reuters: Germany examines Rosneft arm", "related", "names the subject in the headline"),
    ]
    findings += [_lead(f"ein:{i:09d}", f"501(c)(3): Rosfest Inc {i}", "unrelated", "name collision") for i in range(20)]
    return _block(
        findings=findings,
        entity_profile=EntityProfile(
            legal_name="PJSC Rosneft Oil Company",
            lei="253400JT3MQWNDKMJE44",
            status="ACTIVE",
            jurisdiction="RU",
            registered_address="Sofiyskaya nab. 26/1, Moscow",
            parents=["Russian Federation"],
            sources=["gleif"],
        ),
        sanctions=SanctionsScreening(
            status="partial",
            screened=["Canada SEMA"],
            not_screened=["OpenSanctions (HTTP 401: API key missing)", "OFAC SDN: not queried"],
            hits=[
                {
                    "list": "Canada SEMA",
                    "name": "ROSNEFT OIL COMPANY",
                    "match": "soft_name",
                    "url": "https://www.international.gc.ca/sema",
                    "node_id": "lei:253400JT3MQWNDKMJE44",
                }
            ],
        ),
        ownership=OwnershipBlock(levels_walked=2, unresolved=["lei:253400JT3MQWNDKMJE44"]),
        coverage=[
            CoverageRow(source_class="sanctions_pep", searched=True, sources=["ca_sanctions"],
                        skipped=["opensanctions"], outcome="hit"),
            CoverageRow(source_class="beneficial_ownership", searched=False, outcome="not_searched"),
        ],
        escalation_triggers=[
            EscalationTrigger(trigger="Sanctions hit", fired=True, why="Canada SEMA soft name match"),
            EscalationTrigger(trigger="Nominee chain", fired=False),
        ],
        handoff_sheet=["Run through licensed database: Behrenstrasse 18, Berlin, DE (address; unverified lead)"],
        falsifiers=[f"{LEAD_SENTENCE_START}'501(c)(3): Rosfest Inc {i}' (ein:{i:09d})." for i in range(20)]
        + ["A registry extract showing a different owner on the same date"],
    )


def _bombardier_block() -> PIBlock:
    findings = [
        _lead("wikidata:Q333498", "Wikidata Q333498: Bombardier", "related", "name match to the subject"),
        _lead("wikidata:Q378740", "Wikidata Q378740: Incentro", "related", "shared registry address"),
        _lead("wikidata:Q1", "Wikidata Q1: Bombardier tram model", "related", "same brand family"),
    ]
    return _block(
        engagement=_engagement(engagement_id="pi_df875e6f6b"),
        findings=findings + [_lead(f"x:{i}", f"Unrelated tram record {i}", "unrelated") for i in range(5)],
        sanctions=SanctionsScreening(status="partial", screened=["Canada SEMA"], not_screened=["OpenSanctions"]),
        ownership=OwnershipBlock(levels_walked=1, unresolved=["lei:W7L3VLU8EHQY34Z36697"]),
        coverage=[
            CoverageRow(source_class="corporate_registry", searched=True, sources=["gleif", "sec_edgar"],
                        skipped=["nonprofit_990s"], outcome="hit"),
            CoverageRow(source_class="court_dockets", searched=False, outcome="not_searched"),
        ],
        evidence_gaps=["company:bombardier_inc: no dated evidence between 2008-03-17 and 2026-09-07 (6748 days)."],
        handoff_sheet=["Run through licensed database: 400 Cote-Vertu Ouest, Dorval, CA (address; unverified lead)"],
    )


# ------------------------------------------------------------------ structure


def test_new_sections_sit_after_engagement_and_findings():
    headings = _h2(_render(_rosneft_block()))
    assert headings.index("Entity profile") == headings.index("Engagement & scope") + 1
    assert headings.index("Sanctions screening") == headings.index("Findings") + 1
    assert headings[0] == "Bottom line"


def test_empty_block_still_has_both_new_sections():
    sections = _sections(_render(_block()))
    assert sections["Entity profile"] == "None. No registry match for the subject."
    assert "not_run" in sections["Sanctions screening"]
    assert NAME_MATCH_SENTENCE in sections["Sanctions screening"]


# ------------------------------------------------------------------ bottom line: sanctions first


def test_sanctions_hit_leads_the_bottom_line_with_the_exact_wording():
    bottom = _bottom(_render(_rosneft_block()))
    assert bottom.startswith("- **Sanctions:** soft name match to ROSNEFT OIL COMPANY on Canada SEMA; ")
    assert f"{SOFT_HIT_SENTENCE}." in bottom
    assert "Rosfest" not in bottom  # the unrelated nonprofit no longer leads


def test_sanctions_hit_names_several_lists_and_names():
    block = _block(
        sanctions=SanctionsScreening(
            status="lists_run",
            screened=["Canada SEMA", "OFAC SDN"],
            hits=[
                {"list": "Canada SEMA", "name": "ACME OIL", "url": "https://a.example/x"},
                {"list": "OFAC SDN", "name": "ACME OIL", "url": "https://b.example/y"},
                {"list": "OFAC SDN", "name": "ACME TRADING", "url": "https://b.example/z"},
            ],
        )
    )
    bottom = _bottom(_render(block))
    assert "soft name match to ACME OIL, ACME TRADING on Canada SEMA, OFAC SDN;" in bottom


def test_partial_screening_without_hit_never_says_no_sanctions():
    bottom = _bottom(_render(_bombardier_block()))
    assert _bullet(_render(_bombardier_block()), "Sanctions").startswith(
        "partial; Screened: Canada SEMA; NOT screened: OpenSanctions."
    )
    assert "no sanctions" not in bottom.lower()
    assert "SANCTIONS:" not in bottom


def test_not_run_status_is_stated_not_implied_clear():
    bottom = _bottom(_render(_block()))
    assert bottom.startswith("- **Sanctions:** not_run;")
    assert "NOT screened:" in bottom
    assert "no sanctions" not in bottom.lower()


def test_hit_with_partial_screening_keeps_the_not_screened_lists_visible():
    bottom = _bottom(_render(_rosneft_block()))
    # Requirement change (2026-11-09): the Bottom line names the lists only; the per-list reasons moved to
    # the Sanctions screening section so the paragraph stays readable.
    assert "NOT screened: OpenSanctions, OFAC SDN" in bottom
    assert "HTTP 401: API key missing" in "\n".join(_render(_rosneft_block()).split("## Sanctions screening", 1)[1:])


def test_fifty_percent_flags_and_entity_profile_follow_sanctions():
    block = _rosneft_block().model_copy(
        update={"ownership": OwnershipBlock(levels_walked=1, blocked_by_50_rule=["lei:BLOCKED"])}
    )
    bottom = _bottom(_render(block))
    assert bottom.index("soft name match") < bottom.index("50%") < bottom.index("**Registry:**")
    assert _bullet(_render(block), "Registry").startswith(
        "PJSC Rosneft Oil Company, LEI 253400JT3MQWNDKMJE44, ACTIVE, RU"
    )


def test_no_entity_profile_means_no_registry_line():
    assert "Registry:" not in _bottom(_render(_bombardier_block()))


def test_counts_only_relevant_findings_and_reports_the_set_aside_ones():
    bottom = _bottom(_render(_rosneft_block()))
    assert _bullet(_render(_rosneft_block()), "Findings").startswith("3 relevant (3 lead)")
    assert "20 unrelated or low-relevance records were set aside (see JSON)" in bottom


def test_no_set_aside_phrase_when_everything_is_relevant():
    block = _block(findings=[_lead("n1", "Solo", "subject")])
    assert "set aside" not in _bottom(_render(block))


def test_biggest_gap_priority_contradiction_beats_unresolved_ownership():
    block = _rosneft_block().model_copy(
        update={"contradictions": [Contradiction(kind="dissolved_then_active", description="Event after end")]}
    )
    bottom = _bottom(_render(block))
    assert _bullet(_render(block), "Biggest gap").startswith(
        "a contradiction between records (dissolved_then_active: Event after end)"
    )
    assert bottom.index("Biggest gap") < bottom.index("ownership unresolved")


def test_biggest_gap_unresolved_ownership_and_also_open_items():
    markdown = _render(_rosneft_block())
    assert _bullet(markdown, "Biggest gap").startswith(
        "ownership unresolved at PJSC Rosneft Oil Company (lei:253400JT3MQWNDKMJE44)"
    )
    assert "expected source classes not searched: beneficial_ownership" in _bullet(markdown, "Not covered")


def test_next_step_comes_from_a_fired_escalation_trigger_first():
    bottom = _bottom(_render(_rosneft_block()))
    assert "**Next step:** escalate, trigger fired: Sanctions hit (Canada SEMA soft name match)" in bottom
    assert "licensed database" not in bottom


def test_next_step_counts_further_fired_triggers():
    block = _rosneft_block().model_copy(
        update={
            "escalation_triggers": [
                EscalationTrigger(trigger="Sanctions hit", fired=True, why="soft match"),
                EscalationTrigger(trigger="Nominee chain", fired=True, why="registered agent"),
                EscalationTrigger(trigger="Cross-border", fired=True),
            ]
        }
    )
    assert "(2 further fired triggers)" in _bottom(_render(block))


def test_next_step_falls_back_to_handoff_then_custodian_then_none():
    # The fallback chain is the one for a person subject; an entity subject goes to the primary registry instead
    # (final-verifier P4, tested in test_pi_report_v4), so these three blocks are built for a person.
    person = _engagement(subject_is_person=True)
    handoff_only = _rosneft_block().model_copy(update={"escalation_triggers": [], "engagement": person})
    assert "**Next step:** Run through licensed database: Behrenstrasse 18" in _bottom(_render(handoff_only))
    custodian = _block(
        engagement=person,
        custodians=[Custodian(finding="phone", custodian="Carrier X", instrument="production order",
                              jurisdiction="ca-on")],
        escalation_triggers=[EscalationTrigger(trigger="Sanctions hit", fired=False)],
    )
    assert "Carrier X" in _bottom(_render(custodian))
    assert "No escalation indicated." in _bottom(_render(_block(engagement=person)))


def test_bottom_line_stays_within_six_bullets_on_both_fixtures():
    for block in (_rosneft_block(), _bombardier_block(), _block()):
        bullets = _bottom(_render(block)).splitlines()
        assert 3 <= len(bullets) <= 6, bullets


# ------------------------------------------------------------------ strongest finding


def test_tied_top_rank_names_no_single_strongest_finding():
    bottom = _bottom(_render(_bombardier_block()))
    assert "no single strongest finding (3 tied at lead)" in bottom
    assert "Strongest finding:" not in bottom
    assert "Q333498" not in bottom


def test_a_lone_top_finding_is_named_with_a_hedge_when_it_is_only_a_lead():
    block = _block(
        findings=[
            _lead("n1", "Alpha", "subject", source_count=2, finding_label=FindingLabel.PROBABLE),
            _lead("n2", "Beta", "related"),
        ]
    )
    bottom = _bottom(_render(block))
    assert "Strongest finding: Alpha, labelled probable on 2 sources" in bottom
    lead_only = _bottom(_render(_block(findings=[_lead("n1", "Solo", "subject")])))
    assert "Strongest finding: Solo, labelled lead on 1 source (a lead, not established;" in lead_only


def test_strong_but_unrelated_finding_is_never_the_strongest():
    block = _block(
        findings=[
            _lead("n1", "Namesake Foundation", "unrelated", source_count=4, finding_label=FindingLabel.CONFIRMED),
            _lead("n2", "Real Subject", "subject"),
        ]
    )
    bottom = _bottom(_render(block))
    assert "Strongest finding: Real Subject" in bottom
    assert "Namesake" not in bottom
    assert "1 unrelated or low-relevance record" in bottom


def test_two_findings_tied_on_label_but_not_source_count_are_not_a_tie():
    block = _block(
        findings=[
            _lead("n1", "Three", "subject", source_count=3, finding_label=FindingLabel.CONFIRMED),
            _lead("n2", "Five", "subject", source_count=5, finding_label=FindingLabel.CONFIRMED),
        ]
    )
    assert "Strongest finding: Five, labelled confirmed on 5 sources" in _bottom(_render(block))


def test_no_relevant_findings_says_so_and_counts_the_rest():
    block = _block(findings=[_lead("n1", "Noise", "unrelated"), _lead("n2", "Unknown thing", "unknown")])
    bottom = _bottom(_render(block))
    assert "No finding is rated subject or related" in bottom
    assert "2 unrelated or low-relevance records were set aside (see JSON)" in bottom


# ------------------------------------------------------------------ findings table


def test_findings_table_shows_only_subject_and_related_rows_with_relevance_column():
    findings = _sections(_render(_rosneft_block()))["Findings"]
    assert "| Finding | Label | Sources | Freshness | Relevance |" in findings
    rows = [ln for ln in findings.splitlines() if ln.startswith("| ") and "Finding | Label" not in ln
            and "--- |" not in ln]
    assert len(rows) == 3
    assert "Rosfest" not in findings
    assert "20 records of unrelated or unknown relevance omitted here; they are in the JSON result" in findings


def test_related_rows_show_their_reason_and_subject_rows_do_not_need_one():
    findings = _sections(_render(_rosneft_block()))["Findings"]
    related = next(ln for ln in findings.splitlines() if "Rosneft Deutschland" in ln)
    assert "related: subsidiary named in the registry parent link" in related
    subject = next(ln for ln in findings.splitlines() if "PJSC Rosneft Oil Company" in ln)
    assert "| subject |" in subject


def test_omitted_line_is_singular_for_one_record_and_absent_for_zero():
    one = _block(findings=[_lead("n1", "Keep", "subject"), _lead("n2", "Drop", "unknown")])
    assert "1 record of unrelated or unknown relevance omitted here" in _sections(_render(one))["Findings"]
    none = _block(findings=[_lead("n1", "Keep", "subject")])
    assert "omitted here" not in _sections(_render(none))["Findings"]


def test_findings_with_nothing_relevant_starts_with_none_and_still_counts_the_omitted():
    block = _block(findings=[_lead("n1", "Drop", "unrelated")])
    findings = _sections(_render(block))["Findings"]
    assert findings.startswith("None.")
    assert "1 record of unrelated or unknown relevance omitted here" in findings


def test_relevant_findings_are_still_capped_at_25_rows():
    findings = [_lead(f"n{i}", f"Rel {i:02d}", "subject") for i in range(30)]
    findings += [_lead(f"u{i}", f"Unrel {i}", "unrelated") for i in range(4)]
    section = _sections(_render(_block(findings=findings)))["Findings"]
    rows = [ln for ln in section.splitlines() if ln.startswith("| ") and "Finding | Label" not in ln
            and "--- |" not in ln]
    assert len(rows) == 25
    assert "5 further lead-only findings omitted here; they are in the JSON result" in section
    assert "4 records of unrelated or unknown relevance omitted here" in section


def test_label_is_still_capped_by_source_count_in_the_new_table():
    block = _block(findings=[_lead("n1", "Overclaimed", "subject", finding_label=FindingLabel.CONFIRMED)])
    row = next(ln for ln in _sections(_render(block))["Findings"].splitlines() if "Overclaimed" in ln)
    assert "| lead |" in row and "| confirmed |" not in row


# ------------------------------------------------------------------ entity profile section


def test_entity_profile_table_lists_the_registry_fields():
    section = _sections(_render(_rosneft_block()))["Entity profile"]
    assert "| Field | Value |" in section
    for expected in ("PJSC Rosneft Oil Company", "253400JT3MQWNDKMJE44", "ACTIVE", "RU", "Sofiyskaya nab. 26/1",
                     "Russian Federation", "gleif"):
        assert expected in section
    assert not section.startswith("None.")


def test_entity_profile_absent_says_no_registry_match():
    assert _sections(_render(_bombardier_block()))["Entity profile"] == "None. No registry match for the subject."


def test_entity_profile_with_blank_fields_shows_not_recorded():
    block = _block(entity_profile=EntityProfile(legal_name="Only Name Ltd"))
    section = _sections(_render(block))["Entity profile"]
    assert "Only Name Ltd" in section and "not recorded" in section


# ------------------------------------------------------------------ sanctions section


def test_sanctions_section_shows_status_screened_not_screened_and_hits():
    section = _sections(_render(_rosneft_block()))["Sanctions screening"]
    assert "partial" in section
    assert "| List |" in section and "Canada SEMA" in section
    assert "| List | Reason |" in section
    not_screened = next(ln for ln in section.splitlines() if ln.startswith("| OpenSanctions"))
    assert "HTTP 401: API key missing" in not_screened
    assert "| OFAC SDN | not queried |" in section
    hit = next(ln for ln in section.splitlines() if "ROSNEFT OIL COMPANY" in ln)
    assert "SOFT MATCH: verify on primary list" in hit
    assert "https://www.international.gc.ca/sema" in hit
    assert "Canada SEMA" in hit
    assert NAME_MATCH_SENTENCE in section


def test_sanctions_section_partial_never_reads_as_clearance():
    section = _sections(_render(_bombardier_block()))["Sanctions screening"]
    assert "No hits" not in section or "not clearance" in section
    assert "not clearance" in section
    assert NAME_MATCH_SENTENCE in section


def test_sanctions_section_without_hits_says_so_per_status():
    block = _block(sanctions=SanctionsScreening(status="lists_run", screened=["Canada SEMA", "OFAC SDN"]))
    section = _sections(_render(block))["Sanctions screening"]
    assert "lists_run" in section
    assert "No hit on the lists screened" in section
    assert "SOFT MATCH" not in section


def test_sanctions_tables_keep_the_column_count_with_pipes_in_cells():
    block = _block(
        sanctions=SanctionsScreening(
            status="partial",
            screened=["A|B"],
            not_screened=["C|D (reason | detail)"],
            hits=[{"list": "L|1", "name": "N|1", "url": "https://e.example/?a=1|2"}],
        )
    )
    section = _sections(_render(block))["Sanctions screening"]
    for needle, columns in (("A\\|B", 1), ("C\\|D", 2), ("N\\|1", 4)):
        row = next(ln for ln in section.splitlines() if ln.startswith("|") and needle in ln)
        assert _unescaped_pipes(row) == columns + 1, row


# ------------------------------------------------------------------ falsifier collapse


def test_repeated_single_source_lead_lines_collapse_into_one_summary_line():
    section = _sections(_render(_rosneft_block()))["What would change this conclusion"]
    lines = [ln for ln in section.splitlines() if ln.startswith("- ")]
    assert len(lines) == 2
    summary = next(ln for ln in lines if "single-source lead" in ln)
    assert "20 single-source leads" in summary
    assert summary.count("'") <= 10  # at most five quoted names
    assert "and 15 more" in summary
    assert "- A registry extract showing a different owner on the same date" in lines


def test_summary_names_relevant_leads_before_unrelated_ones():
    block = _rosneft_block().model_copy(
        update={
            "falsifiers": [f"{LEAD_SENTENCE_START}'501(c)(3): Rosfest Inc {i}' (ein:{i:09d})." for i in range(20)]
            + [f"{LEAD_SENTENCE_START}'Rosneft Deutschland' (wikidata:Q118611133)."]
        }
    )
    summary = next(ln for ln in _sections(_render(block))["What would change this conclusion"].splitlines()
                   if "single-source" in ln)
    assert summary.index("Rosneft Deutschland") < summary.index("Rosfest Inc 0")


def test_a_single_lead_line_is_left_as_it_is():
    line = f"{LEAD_SENTENCE_START}'Only One' (n1)."
    section = _sections(_render(_block(falsifiers=[line])))["What would change this conclusion"]
    assert f"- {line}" in section


def test_collapsed_falsifiers_still_respect_the_twelve_line_cap():
    falsifiers = [f"Distinct statement {i}" for i in range(20)]
    falsifiers += [f"{LEAD_SENTENCE_START}'Lead {i}' (n{i})." for i in range(9)]
    section = _sections(_render(_block(falsifiers=falsifiers)))["What would change this conclusion"]
    lines = [ln for ln in section.splitlines() if ln.startswith("- ")]
    assert len(lines) == 13
    assert "more (see the JSON result)" in lines[-1]


# ------------------------------------------------------------------ Markdown hygiene


HOSTILE = "[click](javascript:alert(1)) `code` <img src=x onerror=alert(1)> | pipe\n## Injected"


def _assert_no_live_markup(markdown: str) -> None:
    assert "[click](javascript" not in markdown
    assert not re.search(r"(?<!\\)\[click\]", markdown)
    assert not re.search(r"(?<!\\)<img", markdown)


def test_hostile_strings_are_inert_in_table_cells():
    block = _block(
        findings=[_lead("n1", HOSTILE, "subject")],
        entity_profile=EntityProfile(legal_name=HOSTILE, registered_address=HOSTILE),
        sanctions=SanctionsScreening(
            status="partial", screened=[HOSTILE], not_screened=[HOSTILE],
            hits=[{"list": HOSTILE, "name": HOSTILE, "url": "javascript:alert(1)"}],
        ),
        false_link_flags=[{"node_id": HOSTILE, "reason": HOSTILE, "severity": HOSTILE}],
        custodians=[Custodian(finding=HOSTILE, custodian=HOSTILE, instrument=HOSTILE, jurisdiction=HOSTILE,
                              note=HOSTILE)],
    )
    report = _render(block)
    _assert_no_live_markup(report)
    assert _h2(report).count("Injected") == 0
    for line in _sections(report)["Findings"].splitlines():
        if line.startswith("| ") and "click" in line:
            assert _unescaped_pipes(line) == 6, line  # 5 columns


def test_hostile_strings_are_inert_in_the_bottom_line():
    block = _block(
        findings=[_lead("n1", HOSTILE, "subject")],
        sanctions=SanctionsScreening(
            status="partial", screened=[HOSTILE], not_screened=[HOSTILE], hits=[{"list": HOSTILE, "name": HOSTILE}]
        ),
        entity_profile=EntityProfile(legal_name=HOSTILE, lei=HOSTILE, status=HOSTILE, jurisdiction=HOSTILE),
        ownership=OwnershipBlock(unresolved=[HOSTILE], blocked_by_50_rule=[HOSTILE]),
        evidence_gaps=[HOSTILE],
        escalation_triggers=[EscalationTrigger(trigger=HOSTILE, fired=True, why=HOSTILE)],
    )
    report = _render(block)
    bottom = _bottom(report)
    _assert_no_live_markup(bottom)
    assert all(line.startswith("- **") for line in bottom.splitlines())  # every bullet stays on its own single line
    assert "`code`" not in bottom
    assert "<" not in bottom.replace("\\<", "")
    assert _h2(report).count("Injected") == 0


def test_hostile_strings_are_inert_in_lists_and_the_theory_section():
    block = _block(
        identity_notes=[HOSTILE],
        evidence_gaps=[HOSTILE],
        falsifiers=[HOSTILE],
        contradictions=[Contradiction(kind=HOSTILE, description=HOSTILE, node_ids=[HOSTILE])],
        identifier_warnings=[HOSTILE],
        handoff_sheet=[HOSTILE],
    )
    report = _render(block, hypothesis=HOSTILE, seed_query=HOSTILE)
    _assert_no_live_markup(report)
    assert "Injected" not in _h2(report)


def test_backslash_cannot_cancel_the_escape():
    block = _block(findings=[_lead("n1", "\\[x](javascript:alert(1))", "subject")])
    report = _render(block)
    row = next(ln for ln in report.splitlines() if "javascript" in ln and ln.startswith("| "))
    assert "\\\\\\[x\\](javascript" in row  # escaped backslash, then escaped bracket


def test_custody_digest_keeps_its_code_span_but_a_non_hex_digest_is_escaped():
    from bunnyhole.engine.pi import CustodyEntry

    good = "a" * 64
    block = _block(
        custody=[
            CustodyEntry(receipt_id="r1", tool="t", url="https://e.example", sha256=good,
                         collected_at_utc="2026-11-09T12:00:00+00:00"),
            CustodyEntry(receipt_id="r2", tool="t", url="https://e.example", sha256="`<b>`" + good,
                         collected_at_utc="2026-11-09T12:00:00+00:00"),
        ]
    )
    custody = _sections(_render(block))["Chain of custody"]
    assert f"`{good}`" in custody
    assert "<b>" not in custody


# ------------------------------------------------------------------ ACH note


def _ach(verdict: str = NO_ANOMALY_VERDICT) -> Dict[str, Any]:
    return {
        "primary_question": "What is the structure around 'Rosneft'?",
        "winning_hypothesis": "H2: Independent Entities / Shared Infrastructure or Public Records",
        "h1_score": 33, "h2_score": 36, "h3_score": 0,
        "narrative_verdict": verdict,
    }


def test_ach_note_is_added_when_sanctions_hit_and_ach_reports_no_anomalies():
    theory = _sections(_render(_rosneft_block(), ach_assessment=_ach()))["Client theory vs. evidence"]
    assert ACH_NOTE in theory
    assert NO_ANOMALY_VERDICT in theory  # the ACH text itself is not edited


def test_ach_note_for_the_phrase_no_cross_domain_anomalies():
    theory = _sections(_render(_rosneft_block(), ach=_ach("There are no cross-domain anomalies.")))[
        "Client theory vs. evidence"
    ]
    assert ACH_NOTE in theory


def test_no_ach_note_without_a_sanctions_hit():
    theory = _sections(_render(_bombardier_block(), ach_assessment=_ach()))["Client theory vs. evidence"]
    assert "Note: sanctions screening" not in theory


def test_no_ach_note_when_ach_reports_an_anomaly():
    verdict = "Cross-domain attribution anomalies were detected between the two entities."
    theory = _sections(_render(_rosneft_block(), ach_assessment=_ach(verdict)))["Client theory vs. evidence"]
    assert "Note: sanctions screening" not in theory


def test_no_ach_note_when_there_is_no_ach():
    theory = _sections(_render(_rosneft_block()))["Client theory vs. evidence"]
    assert "Note: sanctions screening" not in theory
