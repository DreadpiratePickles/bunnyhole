"""Quality passes on the PI report for entity due diligence: the bottom line, sanctions honesty and Markdown hygiene.

* Sanctions-first bottom line, relevance filtering, the entity profile, the sanctions screening section, falsifier
  collapse, Markdown hygiene and the ACH sanctions note.
* Attested purpose, soft graph matches, 50% rule honesty and a quieter bottom line.
* Final-verifier findings P1, P3, P4, P5, P7, P8: the bottom line as a short labelled list, the EU list, the custodian
  trigger, the same population as the bottom line, no bare filler, "set aside but possibly relevant".

Pure and deterministic: no network, no model calls. Blocks are built by direct ``PIBlock`` construction (no purpose
gates involved) and mirror the live reports: a Rosneft-like block (soft sanctions hits, partial screening,
unresolved parent, raw node ids in the trigger text) and a Bombardier-like block (no hits, partial screening,
TSX-listed, tied single-source leads, custodian trigger fired by the playbook for every entity). The report
structure and section contracts are in ``test_pi_report_sections.py``.
"""

# Replaces: test_pi_report_v2.py, test_pi_report_v3.py, test_pi_report_v4.py (consolidated 2026-11-09).

from __future__ import annotations

import re
from typing import Any, Dict, List

from pi_helpers import report_block as _block
from pi_helpers import report_engagement as _engagement
from pi_helpers import report_sections as _sections
from pi_helpers import unescaped_pipes as _unescaped_pipes

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
    OwnershipEdge,
    PIBlock,
    SanctionsScreening,
)
from bunnyhole.engine.pi_report import build_pi_report
from bunnyhole.engine.pi_report_common import truncate_words

# ==============================================================================================================
# Shared constants and builders
# ==============================================================================================================


SOFT_HIT_SENTENCE = "verify on the primary list before relying on it"
LEAD_SENTENCE_START = "A second independent source that contradicts, or corroborates, the single-source lead "
NAME_MATCH_SENTENCE = "A name match on a sanctions list is a lead, not a determination."
ACH_NOTE = "Note: sanctions screening returned a soft hit; the ACH assessment does not consider sanctions lists."
NO_ANOMALY_VERDICT = (
    "Current evidence primarily reflects standard regulatory, infrastructure, or public-record footprint "
    "without deterministic cross-domain attribution anomalies."
)


# ------------------------------------------------------------------ fixtures and helpers


def _result(block: PIBlock, **extra: Any) -> Dict[str, Any]:
    result: Dict[str, Any] = dict(extra)
    result["pi"] = block.model_dump(mode="json")
    return result


def _render(block: PIBlock, **extra: Any) -> str:
    return build_pi_report(_result(block, **extra))


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


# ==============================================================================================================
# Sanctions-first bottom line, findings table, entity profile, sanctions section, Markdown hygiene
# ==============================================================================================================

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
    # (final-verifier P4, tested in the P4 section below), so these three blocks are built for a person.
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


# ==============================================================================================================
# Attested purpose, 50% rule honesty, soft graph matches
# ==============================================================================================================


NOT_EVALUABLE = "50%-rule: not evaluable (ownership percentages unknown)"
GRAPH_HEADING = "Other graph entities that match a sanctions-list entry (soft)"


def _primary_hit() -> Dict[str, Any]:
    return {"list": "OFAC SDN", "name": "ROSNEFT TRADING S.A.", "match": "soft: verify on the primary list",
            "url": "https://sanctionssearch.ofac.treas.gov/", "node_id": "sanction:ofac:18299"}


def _graph_hit() -> Dict[str, Any]:
    return {"list": "OFAC SDN", "name": "Rosneft Trading S.A.", "match": "matches a sanctions-list entry (soft)",
            "url": "https://sanctionssearch.ofac.treas.gov/", "node_id": "lei:TRADING00000000000001",
            "graph_match": True, "matched_entry": "ROSNEFT TRADING S.A."}


def _screening(*hits: Dict[str, Any]) -> SanctionsScreening:
    return SanctionsScreening(status="partial", screened=["OFAC SDN"], not_screened=["OpenSanctions"], hits=list(hits))


def _edge(pct: Any) -> OwnershipEdge:
    return OwnershipEdge(child="lei:CHILD", parent="lei:PARENT", pct=pct)


# ---------------------------------------------------------------- attested purpose


def test_engagement_section_shows_the_attested_permissible_purpose_category():
    markdown = _render(_block(engagement=_engagement(purpose_category="counterparty_due_diligence")))
    assert "- **Attested permissible purpose:** counterparty_due_diligence" in _sections(markdown)["Engagement & scope"]


def test_engagement_section_says_not_attested_when_the_category_is_empty():
    markdown = _render(_block())
    assert "- **Attested permissible purpose:** (not attested)" in _sections(markdown)["Engagement & scope"]


# ---------------------------------------------------------------- 50% rule honesty


def test_ownership_section_says_the_50_rule_is_not_evaluable_when_no_percentage_is_known():
    ownership = OwnershipBlock(levels_walked=1, edges=[_edge(None)])
    section = _sections(_render(_block(ownership=ownership)))["Ownership chain"]
    assert NOT_EVALUABLE in section
    flags = section.split("**50%-rule flags (OFAC):**")[1].split("**Unresolved")[0]
    assert "None." not in flags


def test_ownership_section_still_says_none_when_percentages_are_known_and_nothing_is_blocked():
    ownership = OwnershipBlock(levels_walked=1, edges=[_edge(30.0)])
    section = _sections(_render(_block(ownership=ownership)))["Ownership chain"]
    assert NOT_EVALUABLE not in section
    assert "**50%-rule flags (OFAC):**\n- None." in section or "**50%-rule flags (OFAC):**\nNone." in section


def test_bottom_line_carries_the_not_evaluable_note_next_to_a_sanctions_hit():
    block = _block(sanctions=_screening(_primary_hit()), ownership=OwnershipBlock(levels_walked=1, edges=[_edge(None)]))
    assert NOT_EVALUABLE in _sections(_render(block))["Bottom line"]


def test_bottom_line_without_a_hit_does_not_add_the_note():
    block = _block(ownership=OwnershipBlock(levels_walked=1, edges=[_edge(None)]))
    assert NOT_EVALUABLE not in _sections(_render(block))["Bottom line"]


def test_the_escalation_text_is_shown_unchanged_in_the_playbook_table():
    trigger = EscalationTrigger(trigger="Sanctions hit", fired=False, why=f"not fired; {NOT_EVALUABLE}")
    assert NOT_EVALUABLE in _sections(_render(_block(escalation_triggers=[trigger])))["Playbook progress"]


# ---------------------------------------------------------------- soft graph matches


def test_sanctions_section_lists_other_graph_entities_that_match_a_listed_entry():
    section = _sections(_render(_block(sanctions=_screening(_primary_hit(), _graph_hit()))))["Sanctions screening"]
    assert GRAPH_HEADING in section
    tail = section.split(GRAPH_HEADING)[1]
    assert "Rosneft Trading S.A." in tail and "ROSNEFT TRADING S.A." in tail
    assert "lei:TRADING00000000000001" in tail
    assert "SOFT MATCH" in tail


def test_primary_hits_table_does_not_repeat_the_graph_matches():
    section = _sections(_render(_block(sanctions=_screening(_primary_hit(), _graph_hit()))))["Sanctions screening"]
    hits_part = section.split("**Hits:**")[1].split(GRAPH_HEADING)[0]
    assert "sanction:ofac:18299" not in hits_part  # the url column carries the list url, not the node id
    assert "Rosneft Trading S.A." not in hits_part.replace("ROSNEFT TRADING S.A.", "")


def test_the_graph_match_block_is_absent_without_graph_matches():
    section = _sections(_render(_block(sanctions=_screening(_primary_hit()))))["Sanctions screening"]
    assert GRAPH_HEADING not in section


def test_bottom_line_names_the_other_graph_matches_and_keeps_the_primary_hit_first():
    bottom = _sections(_render(_block(sanctions=_screening(_primary_hit(), _graph_hit()))))["Bottom line"]
    assert bottom.startswith("- **Sanctions:** soft name match to ROSNEFT TRADING S.A. on OFAC SDN")
    assert "1 other graph entity" in bottom and "Rosneft Trading S.A." in bottom


def test_graph_matches_alone_are_not_a_primary_hit():
    bottom = _sections(_render(_block(sanctions=_screening(_graph_hit()))))["Bottom line"]
    assert bottom.startswith("- **Sanctions:** partial")


# ---------------------------------------------------------------- findings untouched, no crash on odd rows


def test_a_finding_tagged_as_a_soft_listing_keeps_its_reason_in_the_findings_table():
    finding = Finding(
        node_id="lei:TRADING00000000000001", label="Rosneft Trading S.A. (CH)", finding_label=FindingLabel.LEAD,
        source_count=1, relevance="related",
        relevance_reason="extends the subject name with trading; matches a sanctions-list entry (soft): 'X'",
    )
    markdown = _render(_block(findings=[finding]))
    assert "matches a sanctions-list entry (soft)" in _sections(markdown)["Findings"]


def test_graph_match_rows_with_missing_fields_do_not_break_the_report():
    rows: List[Dict[str, Any]] = [{"graph_match": True}]
    markdown = _render(_block(sanctions=_screening(_primary_hit(), *rows)))
    assert "## Sanctions screening" in markdown


def test_node_names_in_the_bottom_line_drop_the_leading_emoji():
    block = _block(ownership=OwnershipBlock(levels_walked=1, unresolved=["lei:X1"]))
    markdown = build_pi_report({"pi": block.model_dump(mode="json"),
                                "nodes": [{"id": "lei:X1", "label": "\U0001f451 Acme Parent Ltd (RU)"}]})
    bottom = _sections(markdown)["Bottom line"]
    assert "Acme Parent Ltd (RU) (lei:X1)" in bottom and "\U0001f451" not in bottom


# ==============================================================================================================
# Final verifier: labelled bottom line, EU list, custodian trigger, filler, set-aside findings
# ==============================================================================================================


EU_ENTRY = "EU Consolidated List: not automated (verify at https://www.sanctionsmap.eu/)"
SANCTIONS_TRIGGER = "A sanctions hit, 50% rule block or PEP link: refer to compliance counsel."
NOMINEE_TRIGGER = "The ownership chain ends at a nominee or secrecy jurisdiction."
CUSTODIAN_TRIGGER = "Non-public company records are needed: counsel for a production order."
BULLET_LABELS = ["Sanctions", "Registry", "Findings", "Biggest gap", "Not covered", "Next step"]


def _bullets(markdown: str) -> Dict[str, str]:
    """{label: text} of the Bottom line bullets (each is one line `- **Label:** text`)."""
    found: Dict[str, str] = {}
    for line in _sections(markdown)["Bottom line"].splitlines():
        match = re.match(r"^- \*\*(?P<label>[^*]+):\*\* (?P<text>.*)$", line)
        assert match, f"not a labelled bullet: {line!r}"
        found[match.group("label")] = match.group("text")
    return found


def _subject_lead(node_id: str, label: str, relevance: str = "subject", **kw: Any) -> Finding:
    return Finding(node_id=node_id, label=label, finding_label=kw.pop("finding_label", FindingLabel.LEAD),
                   source_count=kw.pop("source_count", 1), relevance=relevance, **kw)


def _tsx_listed_block(**overrides: Any) -> PIBlock:
    """Bombardier-like: a registry profile, nothing sanctioned, the custodian trigger fired by the playbook."""
    fields: Dict[str, Any] = {
        "findings": [_subject_lead("lei:W7L3", "BOMBARDIER INC. (CA-QC)"), _subject_lead("article:1", "News: Bombardier wins an order",
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
        findings=[_subject_lead("n1", long_name), _subject_lead("n2", "Another " + long_name)],
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
        findings=[_subject_lead("sanction:ca:1_part_2-821-rosneft_pjsc", "⛔ Rosneft PJSC"),
                  _subject_lead("sanction:ofac:17022", "OPEN JOINT-STOCK COMPANY ROSNEFT OIL COMPANY")],
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
    findings = [_subject_lead(f"n{i}", f"Subject record {i}") for i in range(3)] + [
        _subject_lead(f"u{i}", f"Unknown record {i}", "unknown") for i in range(3)]
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
            _subject_lead("lei:253400JT3MQWNDKMJE44", "PJSC Rosneft Oil Company"),
            _subject_lead("sec:1", "SEC Form 20-F: BP PLC (BP, BPAQF) (CIK 0000313807)", "unrelated"),
            _subject_lead("hn:1", "HN (@x): BP to Exit Its 20% Shareholding in Russian Oil P...", "unrelated"),
            _subject_lead("ein:1", "501(c)(3): Rosfest Inc (Sarasota, FL)", "unrelated"),
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
    extra = [_subject_lead(f"sec:{i}", f"SEC Form 6-K: BP PLC filing {i}", "unrelated") for i in range(10)]
    block = _set_aside_block(findings=_set_aside_block().findings + extra)
    tail = _sections(_render(block))["Findings"].split("Set aside but possibly relevant (mentions a related party):")[1]
    assert len(re.findall(r"\(mentions BP PLC\)", tail.split("\n\n")[0])) == 5
    quiet = _set_aside_block(entity_profile=None)
    assert "possibly relevant" not in _sections(_render(quiet))["Findings"]


def test_a_short_name_must_match_a_whole_word_not_a_substring():
    block = _set_aside_block(findings=[_subject_lead("n1", "Subject"), _subject_lead("x", "Bpmn tooling guide", "unrelated")])
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
